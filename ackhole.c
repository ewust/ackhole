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

    int current_running;
    int max_concurrent;

    struct flow_map conn_map;

    struct event *status_ev;
    struct event *pcap_ev;
    struct bufferevent *stdin_bev;

    int stdin_closed;

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

void pcap_cb(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;
    const char *pkt;
    struct pcap_pkthdr pkt_hdr;
    char src_ip[16];
    char dst_ip[16];
    struct timeval tv;
    int64_t diff;

    gettimeofday(&tv, NULL);


    //log_trace("pcap_cb", "(%d, %02x, %p)", fd, what, ptr);

    pkt = pcap_next(conf->pcap, &pkt_hdr);
    if (pkt == NULL) {
        return;
    }

    diff = (tv.tv_sec - pkt_hdr.ts.tv_sec)*1000000 + (tv.tv_usec - pkt_hdr.ts.tv_usec);

    struct iphdr *ip_ptr = (struct iphdr *)(pkt + sizeof(struct ether_header));
    if (ip_ptr->protocol != IPPROTO_TCP) {
        return;
    }

    struct tcphdr *th = (struct tcphdr*)(pkt + sizeof(struct ether_header) + (4*(ip_ptr->ihl)));
    inet_ntop(AF_INET, &ip_ptr->saddr, src_ip, 16);
    inet_ntop(AF_INET, &ip_ptr->daddr, dst_ip, 16);
    log_debug("ackhole", "%s:%d -> %s:%d, %d bytes, flags SYN[%d] ACK[%d] PSH[%d] diff %d ms", 
            src_ip, ntohs(th->source), dst_ip, ntohs(th->dest), pkt_hdr.caplen, th->syn, th->ack, th->psh, diff/1000);

    if (ntohs(th->source) != 80) {
        return;
    }

    uint32_t ip = ip_ptr->saddr;
    uint16_t port = th->dest;

    struct flow *fl = lookup_flow(&conf->conn_map, ip, port);
    if (fl == NULL) {
        return;
    }

    fl->value.seq = th->seq;
    fl->value.ack = th->ack;
    fl->value.num_recv++;

    conf->stats.tot_pkts++;
}

void print_status(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;

    log_info("ackhole", "%lu pkts", conf->stats.tot_pkts);

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
    struct config *conf = ptr;

    log_trace("conn_eventcb", "(%p, %d, %p)", bev, events, ptr);

    if (events & BEV_EVENT_CONNECTED) {
        log_debug("ackhole", "connected");
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

    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"concurrent", optional_argument, 0, 'c'},
        {"iface",   optional_argument, 0, 'i'},
        {"file", optional_argument, 0, 'f'},
        {0, 0, 0, 0}
    };
    while (1) {
        c = getopt_long(argc, argv, "i:f:", long_options, &option_index);
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
        if (pcap_set_buffer_size(conf.pcap, 100*1024*1024)) {
            printf("pcap_set buffer size error\n");
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
        conf.pcap_fd = pcap_fileno(conf.pcap);
    } else {
        conf.pcap_fd = fileno(pcap_fstream);
    }

    // Setup libevent
    event_init();
    conf.base = event_base_new();

    // Event on pcap fd EV_READ
    conf.pcap_ev = event_new(conf.base, conf.pcap_fd, EV_READ|EV_PERSIST, pcap_cb, &conf);
    event_add(conf.pcap_ev, NULL);

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


