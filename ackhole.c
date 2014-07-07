#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <string.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include "logger.h"

#define HTTP_REQ "GET / HTTP/1.1\r\nHost: www.example.cn\r\nX-Ignore: LNldcCbWyE\x7f}A|pgkRhtTeUor`qw@IuQ~zOv]mxiZHYDBasnKPJjG\\F_fM[^V{SX\r\n"
#define TCP_EXPIRE_SECS 300


void stdin_readcb(struct bufferevent *bev, void *arg);

struct stats_t {
    uint64_t    tot_pkts;
    uint32_t    tot_flows;
};

// Generic type used in a map[(ip,port)] -> flow.value
struct flow_t {
    struct config *conf;

    int sock;
    struct bufferevent *bev;

    uint32_t seq;
    uint32_t ack;
    uint32_t num_recv;

    // These are for our pcap state machine; as we receive packets we go through these phases
    enum {STATE_CONNECTING, STATE_SYN_SENT, STATE_SYN_RECV, STATE_DATA_SENT, STATE_DATA_ACK, STATE_ACK_RESPONSE} state;

    int connected;
    int sent_acks;

    // The ack (from server) before we can actually send ACKS. This ACKs our incomplete HTTP_REQ
    int waiting_ack;

    struct timeval first_syn_ts;
    struct timeval first_response_ts;

    struct timeval expire;
};

struct flow {
    // Key
    struct flow *next;
    uint32_t ip;
    uint16_t port;

    // Value
    struct flow_t value;
};

// Linked list of keys
struct flow_key {
    struct flow_key *next;  // next key

    struct flow *cur;
};

struct flow_map {
    struct flow **map;  // actual map

    struct flow_key *keys;
};

#define MAP_ENTRIES         (1<<18)
#define HASH_IDX(ip,port)   (((59*ip)^port)%MAP_ENTRIES)

struct config {
    char    *dev;
    pcap_t  *pcap;
    int      pcap_fd;
    struct event_base *base;
    uint32_t saddr;

    int current_running;
    int max_concurrent;

    struct flow_map conn_map;

    struct event *status_ev;
    struct event *flush_ev;
    struct event *pcap_ev;
    struct bufferevent *stdin_bev;

    int stdin_closed;

    int raw_sock;

    struct stats_t  stats;
};


struct flow *add_flow(struct flow_map *conn_map, struct flow *new_flow)
{
    struct flow *cur;
    int idx = HASH_IDX(new_flow->ip, new_flow->port);

    log_trace("add_flow", "(%p, %08x:%04x)", conn_map, new_flow->ip, new_flow->port);

    // Add to head of keys linked list
    struct flow_key *new_key = malloc(sizeof(struct flow_key));
    new_key->next = conn_map->keys;
    new_key->cur = new_flow;
    conn_map->keys = new_key;

    // Add to the hash map
    cur = conn_map->map[idx];
    if (cur == NULL) {
        conn_map->map[idx] = new_flow;
        return;
    }

    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = new_flow;
}

// This function is common to TCP and UDP (DNS)
// ip is the server IP
// port is the client port
// For TCP, txid is set to 0.
// TODO: support client IP
struct flow *lookup_flow(struct flow_map *conn_map, uint32_t ip, uint16_t port)
{
    struct flow *ret;

    log_trace("lookup_flow", "(%p, %08x, %04x)", conn_map, ip, port);

    ret = conn_map->map[HASH_IDX(ip, port)];
    while (ret != NULL) {
        if (ret->ip == ip && ret->port == port) {
            return ret;
        }
        ret = ret->next;
    }

    return NULL;
}

void print_flow(struct flow *fl);
void print_status(evutil_socket_t fd, short what, void *ptr);

void cleanup_flow(struct flow_key *key, struct flow_key *prev_key, struct config *conf)
{
    struct flow *cur_flow = key->cur;   // this is just fl
    int idx = HASH_IDX(cur_flow->ip, cur_flow->port);

    log_debug("ackhole", "cleaning up flow %08x:%04x\n", key->cur->ip, key->cur->port);
    if (cur_flow->value.state == STATE_DATA_ACK && cur_flow->value.sent_acks) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        memcpy(&cur_flow->value.first_response_ts, &tv, sizeof(struct timeval));
        cur_flow->value.state = STATE_ACK_RESPONSE;
        print_flow(cur_flow);
    }

    // Find previous element in hashtable
    struct flow *prev_bucket = NULL;
    struct flow *cur_bucket = conf->conn_map.map[idx];
    assert(cur_bucket != NULL);
    while (cur_bucket != NULL && cur_bucket != cur_flow) {
        prev_bucket = cur_bucket;
        cur_bucket = cur_bucket->next;
    }
    assert(cur_bucket == cur_flow);

    // Fixup map linked list
    if (prev_bucket != NULL) {
        prev_bucket->next = cur_flow->next;
    } else {
        // First element in list
        conf->conn_map.map[idx] = cur_flow->next;
    }

    // Close bev
    if (cur_flow->value.bev != NULL) {
        bufferevent_free(cur_flow->value.bev);
    }

    // Remove from keys list
    if (prev_key != NULL) {
        prev_key->next = key->next;
    } else {
        // First key in list, set head of list
        conf->conn_map.keys = key->next;
    }
    // Free key entry
    free(key);

    // Free self
    free(cur_flow);

    //conf->stats.cur_flows--;
    conf->current_running--;

    if (evbuffer_get_length(bufferevent_get_input(conf->stdin_bev)) > 0) {
        stdin_readcb(conf->stdin_bev, conf);
    }

    if (conf->stdin_closed && conf->current_running == 0) {
        // Done
        log_info("banner-grab-tcp", "done");
        print_status(0, 0, conf);
        exit(0);
    }

    conf->stats.tot_flows++;
}

int cleanup_expired(struct config *conf)
{
    struct flow_key *cur_key = conf->conn_map.keys;
    struct timeval cur_ts;
    struct flow_key *prev_key = NULL;
    int num_removed = 0;

    // TODO: use packet time or is real time good enough?
    // possible easy fix: pad TCP_EXPIRE_SEC with the max processing delay we expect
    gettimeofday(&cur_ts, NULL);

    while (cur_key != NULL) {
        assert(cur_key->cur != NULL);
        if (cur_key->cur->value.state == STATE_ACK_RESPONSE ||
            (cur_key->cur->value.state != STATE_CONNECTING &&
             (cur_key->cur->value.expire.tv_sec < cur_ts.tv_sec ||
              (cur_key->cur->value.expire.tv_sec == cur_ts.tv_sec &&
              cur_key->cur->value.expire.tv_usec <= cur_ts.tv_usec)))) {
            // Expired
            struct flow_key *tmp_key = cur_key->next;   // because cleanup_flow will free(cur_key)
            cleanup_flow(cur_key, prev_key, conf);
            cur_key = tmp_key;  // Don't update prev_key

            num_removed++;
        } else {
            prev_key = cur_key;
            cur_key = cur_key->next;
        }
    }

    return num_removed;
}



uint16_t tcp_checksum(unsigned short len_tcp,
        uint32_t saddr, uint32_t daddr, struct tcphdr *tcp_pkt)
{
    uint16_t *src_addr = (uint16_t *) &saddr;
    uint16_t *dest_addr = (uint16_t *) &daddr;

    unsigned char prot_tcp = 6;
    unsigned long sum = 0;
    int nleft = len_tcp;
    unsigned short *w;

    w = (unsigned short *) tcp_pkt;
    // calculate the checksum for the tcp header and tcp data
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & ntohs(0xFF00);
    }
    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

#define IP_TCP(ip_hdr)      (struct tcphdr*)(((char *)ip_hdr) + (4 * ip_hdr->ihl))
#define TCP_DATA(tcp_hdr)   (((char *)tcp_hdr) + (4 * tcp_hdr->th_off))


uint16_t csum(uint16_t *buf, int nwords, uint32_t init_sum)
{
    uint32_t sum;

    for (sum=init_sum; nwords>0; nwords--) {
        sum += ntohs(*buf++);
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t tcp_csum(struct iphdr *ip_hdr)
{
    uint32_t sum = 0;
    int tcp_size = ntohs(ip_hdr->tot_len) - sizeof(struct iphdr);
    struct tcphdr *tcph = IP_TCP(ip_hdr);

    sum += ntohs(ip_hdr->saddr&0xffff) + ntohs((ip_hdr->saddr >> 16)&0xffff);
    sum += ntohs(ip_hdr->daddr&0xffff) + ntohs((ip_hdr->daddr >> 16)&0xffff);
    sum += 0x06;    // TCP protocol #define somewhere(?), plz
    sum += tcp_size;
    //printf ("init csum: %x, tcp size: %d\n", sum, tcp_size);

    tcph->check = 0x0000;

    if (tcp_size%2) { //odd tcp_size,
        sum += (((char*)tcph)[tcp_size-1] << 8);
    } 

    return csum((uint16_t*)tcph, tcp_size/2, sum);
}


//warning: unlikely integer overflow on tot_len
//maybe place reasonable constraint on len (<= 10000, jumbo frames?)
int tcp_forge_xmit(struct flow *fl, char *payload, int len, uint32_t saddr, int raw_sock)
{
    int tcp_len = sizeof(struct tcphdr);

    char *forge_again = NULL;
    int forge_again_len = 0;
    if (len > 1448) {   // TODO(ewust): #define, please.
                        // TODO(ewust): this is ETH_MTU - sizeof(ip) - sizeof(tcp)
                        //              which are variable.
        forge_again = payload + 1448;
        forge_again_len = len - 1448;
        len = 1448;
    }

    int tot_len = len + tcp_len + sizeof(struct iphdr);
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    char *data;
    struct sockaddr_in sin;
    int res; 
    
    //set up sin destination
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = fl->ip;
   
    
    ip_hdr = malloc(tot_len);
    if (ip_hdr == NULL) {
        return 1;
    }

    //zero-fill headers
    memset(ip_hdr, 0, sizeof(struct iphdr) + tcp_len);

    //no ip options
    tcp_hdr = (struct tcphdr*)(ip_hdr+1);
    data = (char *)(tcp_hdr) + tcp_len;

    //copy payload data
    if (len != 0) {
        memcpy(data, payload, len);
    }

    //fill in ip header
    ip_hdr->ihl         = sizeof(struct iphdr) >> 2;
    ip_hdr->version     = 4;
    ip_hdr->tot_len     = htons(tot_len);
    ip_hdr->frag_off    = htons(0x4000); //don't fragment
    ip_hdr->ttl         = 64; 
    ip_hdr->id          = 1337;
    ip_hdr->protocol    = IPPROTO_TCP;
    ip_hdr->saddr       = (saddr);
    ip_hdr->daddr       = (fl->ip);

    //fill in tcp header
    tcp_hdr->source     = (fl->port);
    tcp_hdr->dest       = htons(80);
    tcp_hdr->seq        = fl->value.ack;
    tcp_hdr->ack_seq    = htonl(ntohl(fl->value.seq)+100);
    tcp_hdr->doff       = tcp_len >> 2;
    tcp_hdr->ack        = 1;
    if (len != 0) {
        tcp_hdr->psh = 1; // |= TH_PUSH; //0x18; //PSH + ACK
    }
    tcp_hdr->window     = htons(1024);

    tcp_hdr->check = htons(tcp_csum(ip_hdr));
    ip_hdr->check = htons(csum((uint16_t*)ip_hdr, sizeof(struct iphdr)/2, 0));

    res = sendto(raw_sock, ip_hdr, tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));

    if (forge_again == NULL) {  // Normal path, our data fits in one packet.
        free(ip_hdr);
        return (res != tot_len);
    }
    //fl->tcp.seq += len;
    //fl->last_ip_id++;
    // TODO(ewust): does window size shrink here?
    //      If so, we would need to know about window scaling.

    res = tcp_forge_xmit(fl, forge_again, forge_again_len, saddr, raw_sock);

    //set fl back to how it was, caller will likely want to increment in the normal case
    //fl->tcp.seq -= len;

    free(ip_hdr);
    return res;
}




void send_acks(struct flow *fl)
{
    struct config *conf = fl->value.conf;
    char data[100];
    memset(data, 'A', sizeof(data));

    if (conf->saddr == 0) {
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        if (getsockname(fl->value.sock, (struct sockaddr *)&sin, &len) < 0) {
            perror("getsockname");
            return;
        }
        conf->saddr = sin.sin_addr.s_addr;
    }

    int r = tcp_forge_xmit(fl, NULL, 0, conf->saddr, conf->raw_sock);
    log_debug("ackhole", "sent empty ack: %d", r);

    //fl->value.ack = htonl(ntohl(fl->value.ack) + 100);
    // send a data packet while we're at it

    r = tcp_forge_xmit(fl, data, sizeof(data), conf->saddr, conf->raw_sock);

    fl->value.sent_acks = 1;
}

void print_flow(struct flow *fl)
{
    struct config *conf = fl->value.conf;
    int64_t diff = (fl->value.first_response_ts.tv_sec - fl->value.first_syn_ts.tv_sec)*1000000 + (fl->value.first_response_ts.tv_usec - fl->value.first_syn_ts.tv_usec);
    char src_ip[16];
    char dst_ip[16];

    inet_ntop(AF_INET, &conf->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &fl->ip, dst_ip, sizeof(dst_ip));

    fprintf(stderr, "### %s:%d - %s:%d   %ld ms\n", src_ip, ntohs(fl->port), dst_ip, 80, diff/1000);

}

void handle_pkt(u_char *ptr, const struct pcap_pkthdr *pkt_hdr, const u_char* pkt);

void pcap_cb(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;

    log_trace("pcap_cb", "(%d, %02x, %p)", fd, what, ptr);

    int r = pcap_dispatch(conf->pcap, 10000, handle_pkt, (void*)conf);
    if (r < 0) {
        log_error("pcap_cb", "pcap_dispatch returned -1: %s", pcap_geterr(conf->pcap));
    }
}

void handle_pkt(u_char *ptr, const struct pcap_pkthdr *pkt_hdr, const u_char* pkt)
{
    struct config *conf = (struct config *)ptr;
    char src_ip[16];
    char dst_ip[16];
    struct timeval tv;
    int64_t diff;

    gettimeofday(&tv, NULL);

    diff = (tv.tv_sec - pkt_hdr->ts.tv_sec)*1000000 + (tv.tv_usec - pkt_hdr->ts.tv_usec);

    struct iphdr *ip_ptr = (struct iphdr *)(pkt + sizeof(struct ether_header));
    if (ip_ptr->protocol != IPPROTO_TCP) {
        return;
    }

    struct tcphdr *th = (struct tcphdr*)(pkt + sizeof(struct ether_header) + (4*(ip_ptr->ihl)));
    inet_ntop(AF_INET, &ip_ptr->saddr, src_ip, 16);
    inet_ntop(AF_INET, &ip_ptr->daddr, dst_ip, 16);
    log_debug("ackhole", "%s:%d -> %s:%d, %d bytes, flags SYN[%d] ACK[%d] PSH[%d] diff %d ms (win %d)",
            src_ip, ntohs(th->source), dst_ip, ntohs(th->dest), pkt_hdr->caplen, th->syn, th->ack, th->psh, diff/1000, ntohs(th->window));


    uint32_t ip;
    uint16_t port;
    struct flow *fl;


    if (ntohs(th->source) != 80) {
        // client -> server
        ip = ip_ptr->daddr;
        port = th->source;
        fl = lookup_flow(&conf->conn_map, ip, port);

        if (fl == NULL) {
            return;
        }

        log_debug("ackhole", " -> state: %d", fl->value.state);

        fl->value.seq = th->ack_seq;
        //fl->value.ack = th->seq;
        fl->value.num_recv++;

        if (fl->value.state == STATE_CONNECTING && th->syn) {
            log_trace("ackhole", " -> STATE_SYN_SENT");
            fl->value.state = STATE_SYN_SENT;
            memcpy(&fl->value.first_syn_ts, &pkt_hdr->ts, sizeof(struct timeval));
        } else if (fl->value.state == STATE_SYN_RECV && th->psh) {  // Does not support fragments of HTTP_REQ
            fl->value.state = STATE_DATA_SENT;
            fl->value.waiting_ack = htonl(ntohl(th->seq) + strlen(HTTP_REQ));
            log_trace("ackhole", " -> STATE_DATA_SENT (waiting ack %08x", fl->value.waiting_ack);
        }

    } else {

        ip = ip_ptr->saddr;
        port = th->dest;

        fl = lookup_flow(&conf->conn_map, ip, port);
        if (fl == NULL) {
            return;
        }

        log_debug("ackhole", " <- state: %d", fl->value.state);
        //fl->value.seq = th->seq;
        fl->value.ack = th->ack_seq;
        fl->value.num_recv++;

        if (fl->value.state == STATE_SYN_SENT && th->syn && th->ack) {
            log_trace("ackhole", " -> STATE_SYN_RECV");
            fl->value.state = STATE_SYN_RECV;
        } else if (fl->value.state == STATE_DATA_SENT && th->ack && th->ack_seq == fl->value.waiting_ack) {
            log_trace("ackhole", " -> STATE_DATA_ACK");
            fl->value.state = STATE_DATA_ACK; // now we can send acks
        } else if (fl->value.state == STATE_DATA_ACK && fl->value.sent_acks) {
            // Dun dun. the server has responded with data.
            memcpy(&fl->value.first_response_ts, &pkt_hdr->ts, sizeof(struct timeval));
            fl->value.state = STATE_ACK_RESPONSE;
            print_flow(fl);
        }

        if (fl->value.connected && fl->value.state == STATE_DATA_ACK && !fl->value.sent_acks) {
            send_acks(fl);
        }

    }

    // Update flow expire time
    memcpy(&fl->value.expire, &pkt_hdr->ts, sizeof(struct timeval));
    fl->value.expire.tv_sec += TCP_EXPIRE_SECS;

    conf->stats.tot_pkts++;
}

void print_status(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;

    int num_removed = cleanup_expired(conf);

    log_info("ackhole", "%d/%d flows (cleaned up %d) %d flows (%lu pkts)", conf->current_running, conf->max_concurrent, num_removed, conf->stats.tot_flows, conf->stats.tot_pkts);

    pcap_cb(0, 0, conf);

}

void stdin_eventcb(struct bufferevent *bev, short events, void *ptr) {
    struct config *conf = ptr;

    log_trace("stdin_eventcb", "(%p, %d, %p)", bev, events, ptr);

    if (events & BEV_EVENT_EOF) {
        log_debug("ackhole",
                  "received EOF; quitting after buffer empties");
        conf->stdin_closed = 1;
        if (conf->current_running == 0) {
            log_info("ackhole", "done");
            print_status(0, 0, conf);
            exit(0);
        }
    }
}

void conn_eventcb(struct bufferevent *bev, short events, void *ptr)
{
    struct flow *fl = ptr;

    log_trace("conn_eventcb", "(%p, %d, %p)", bev, events, ptr);

    if (events & BEV_EVENT_CONNECTED) {
        log_debug("ackhole", "connected");
        fl->value.connected = 1;
    } else if (events & BEV_EVENT_ERROR) {
         /* An error occured while connecting. */
    } else {
        // TODO: close
    }
}

void make_conn(struct flow *fl)
{
    struct sockaddr_in sin;
    struct config *conf = fl->value.conf;

    log_trace("make_conn", "(%08x)", fl->ip);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    sin.sin_port = htons(0);

    // Bind and get our source port for the conn_map
    fl->value.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (fl->value.sock < 0) {
        perror("socket");
        return;
    }
    evutil_make_socket_nonblocking(fl->value.sock);
    if (bind(fl->value.sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        // TODO: cleanup
        return;
    }

    // Get the port we are bound to
    socklen_t len = sizeof(sin);
    if (getsockname(fl->value.sock, (struct sockaddr *)&sin, &len) < 0) {
        perror("getsockname");
        // Cleanup
        return;
    }

    fl->port = sin.sin_port;
    log_debug("ackhole", "got port %d", ntohs(fl->port));
    add_flow(&conf->conn_map, fl);

    // Connect to this socket
    sin.sin_addr.s_addr = fl->ip;
    sin.sin_port = htons(80);

    fl->value.bev = bufferevent_socket_new(conf->base, fl->value.sock, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(fl->value.bev, NULL, NULL, conn_eventcb, fl);

    if (bufferevent_socket_connect(fl->value.bev,
        (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        /* Error starting connection */
        bufferevent_free(fl->value.bev);
        return;
    }

    bufferevent_write(fl->value.bev, HTTP_REQ, strlen(HTTP_REQ));

}

void stdin_readcb(struct bufferevent *bev, void *arg)
{
    struct evbuffer *in = bufferevent_get_input(bev);
    struct config *conf = arg;

    log_debug("ackhole", "stdin cb %d < %d ?",
        conf->current_running, conf->max_concurrent);

    while (conf->current_running < conf->max_concurrent &&
           evbuffer_get_length(in) > 0) {
        char *ip_str;
        size_t line_len;
        char *line = evbuffer_readln(in, &line_len, EVBUFFER_EOL_LF);
        struct flow *fl;
        if (!line)
            break;
        log_debug("ackhole", "line: %s", line);

        ip_str = line;
        /*
        port_str = strstr(line, ":") + 1;
        if (!port_str)
            port_str = strstr(line, " ") + 1;
        if (!port_str)
            break;

        *(port_str-1) = '\0';
        port = atoi(port_str);
        */
        //printf("scanning %s:%d\n", ip

        conf->current_running++;
        fl = malloc(sizeof(*fl));
        memset(fl, 0, sizeof(*fl));
        fl->ip = inet_addr(ip_str);
        fl->value.conf = conf;
        make_conn(fl);
    }
}



int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct config conf;
    struct bpf_program bpf;
    char *pcap_fname = NULL;
    FILE *pcap_fstream;

    log_init(stdout, ZLOG_TRACE, 0, NULL);
    memset(&conf, 0, sizeof(conf));
    conf.dev = "eth0";
    conf.max_concurrent = 1;
    conf.current_running = 0;
    conf.stdin_closed = 0;
    conf.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);


    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"concurrent", optional_argument, 0, 'c'},
        {"iface",   optional_argument, 0, 'i'},
        {"file", optional_argument, 0, 'f'},
        {"verbosity", optional_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    while (1) {
        c = getopt_long(argc, argv, "c:i:f:v:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;
        case 'c':
            conf.max_concurrent = atoi(optarg);
            break;
        case 'i':
            conf.dev = optarg;
            break;
        case 'f':
            pcap_fname = optarg;
            break;
        case 'v':
            log_init(stdout, atoi(optarg), 0, NULL);
            break;
        }
    }

    //pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    if (pcap_fname != NULL) {
        pcap_fstream = fopen(pcap_fname, "r");
        if (!pcap_fstream) {
            perror("fopen");
            return -1;
        }

        int saved_flags;
        saved_flags = fcntl(fileno(pcap_fstream), F_GETFL);

        fcntl(fileno(pcap_fstream), F_SETFL, saved_flags | O_NONBLOCK);

        conf.pcap = pcap_fopen_offline(pcap_fstream, errbuf);
    } else {
        //conf.pcap = pcap_open_live(conf.dev, 65535, 0, -1, errbuf);
        conf.pcap = pcap_create(conf.dev, errbuf);
    }

    if (conf.pcap == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }


    // file or normal pcap
    if (pcap_fname == NULL) {
        if (pcap_set_timeout(conf.pcap, 1000) != 0) {
            log_error("ackhole", "pcap_set_timeout failed");
            return -1;
        }
        if (pcap_set_buffer_size(conf.pcap, 100*1024*1024)) {
            log_error("ackhole", "pcap_set buffer size error");
            return -1;
        }
        pcap_activate(conf.pcap);
    }

    // Compile the filter expression
    if(pcap_compile(conf.pcap, &bpf, "(tcp and port 80)", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        printf("pcap_compile() failed\n");
        return -1;
    }

    if (pcap_setfilter(conf.pcap, &bpf) < 0)
    {
        printf("pcap_setfilter() failed\n");
        return -1;
    }

    if (pcap_fname == NULL) {
        if (pcap_setnonblock(conf.pcap, 1, errbuf)) {
            log_error("ackhole", "setnonblock failed: %s", errbuf);
            return -1;
        }
        conf.pcap_fd = pcap_fileno(conf.pcap);
    } else {
        conf.pcap_fd = fileno(pcap_fstream);
    }

    // Setup libevent
    event_init();
    conf.base = event_base_new();

    log_debug("ackhole", "conf.pcap_fd = %d", conf.pcap_fd);

    // Event on pcap fd EV_READ
    conf.pcap_ev = event_new(conf.base, conf.pcap_fd, EV_READ|EV_PERSIST, pcap_cb, &conf);
    event_add(conf.pcap_ev, NULL);

    // pcap dispatch timer
    struct timeval pc_ts = {0, 1000*100};   // 100ms
    conf.flush_ev = event_new(conf.base, -1, EV_PERSIST, pcap_cb, &conf);
    event_add(conf.flush_ev, &pc_ts);

    // Status timer
    struct timeval one_sec = {1, 0};
    conf.status_ev = event_new(conf.base, -1, EV_PERSIST, print_status, &conf);
    event_add(conf.status_ev, &one_sec);

    // Stdin
    conf.stdin_bev = bufferevent_socket_new(conf.base, 0, BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(conf.stdin_bev, stdin_readcb, NULL, stdin_eventcb, &conf);
    bufferevent_enable(conf.stdin_bev, EV_READ);

    // Init map
    conf.conn_map.map = calloc(sizeof(struct flow*), MAP_ENTRIES);

    if (pcap_fname == NULL) {
        // pcap live
        event_base_dispatch(conf.base);
    } else {
        printf("reading from file\n");
        while (1) {
            pcap_cb(0, 0, &conf);
        }
    }

    printf("done\n");

    return 0;
}


