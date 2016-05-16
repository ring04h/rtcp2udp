#!/usr/bin/env python
# encoding: utf-8
# bug fix, plz contact ringzero@0x557.org

import socket
import socks

buffsize = 4096 

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 19191) 
socket.socket = socks.socksocket

def tcp_client(rhost, rport):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return client, rhost, rport

def udp_client(rhost, rport):
    client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return client, rhost, rport

# tcp_sock = tcp_client('127.0.0.1', 53)
# tcp_clnt,tcp_host,tcp_port = tcp_sock
# tcp_clnt.connect((tcp_host,tcp_port))
# while True:
#     tcp_data = tcp_clnt.recv(buffsize)
#     print repr(tcp_data)

udp_conn = udp_client('127.0.0.1', 53)
udp_clnt,udp_host,udp_port = udp_conn
udp_clnt.sendto('client\n',(udp_host,udp_port))
udp_clnt.sendto('client2\n',(udp_host,udp_port))
while True:
    udp_data,udp_addr = udp_clnt.recvfrom(buffsize)
    print repr(udp_data), udp_addr
