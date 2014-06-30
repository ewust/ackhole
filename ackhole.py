#!/usr/bin/python

import dpkt
import dnet
import threading
import sys
import socket



conns = {}


def recv_thread():
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind(('wlan0', 0x0800))
    while True:
        eth = dpkt.ethernet.Ethernet(sock.recv(0xffff))
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        ipaddr = socket.inet_ntoa(ip.src)

        print '%s %d' % (ipaddr, tcp.dport)
        if (ipaddr, tcp.dport) in conns:
            conns[(ipaddr, tcp.dport)]['seq'] = tcp.seq
            conns[(ipaddr, tcp.dport)]['ack'] = tcp.ack


            print eth.__repr__()

import time

def connect(ip, port):
    #print 'connecting %s %d' % (ip, port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 0))
    lport = s.getsockname()[1]
    conns[(ip, lport)] = {'sock': s}
    #print '=> %s %d' % (ip, lport)
    s.connect((ip, port))


def read_thread(port):
    for line in sys.stdin:
        connect(line.strip(), port)

t1 = threading.Thread(target=recv_thread, args = ())
t1.daemon = True
t1.start()


# main thread just reads stdin
read_thread(80)

print 'joining...'

#t1.join()

