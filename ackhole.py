#!/usr/bin/python

import dpkt
import dnet
import threading
import sys
import socket



conns = {}


def recv_thread():
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind(('eth0', 0x0800))
    while True:
        eth = dpkt.ethernet.Ethernet(sock.recv(0xffff))
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        ipaddr = socket.inet_ntoa(ip.src)

        if (ipaddr, tcp.sport) in conns:
	        print eth.__repr__()


def connect(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conns[(ip, port)] = s
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

