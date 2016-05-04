#!/usr/bin/env python
# encoding: utf-8
# bug fix, plz contact ringzero@0x557.org

import sys
import socket
import threading
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
)

buffsize = 4096

class PortMap(object):
    """docstring for PortMap"""
    def __init__(self,):
        super(PortMap, self).__init__()
        self.bridge_flag = True

    def tcp_client(self, rhost, rport):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return client, rhost, rport

    def udp_client(self, rhost, rport):
        client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        return client, rhost, rport

    def udp_forward(self,tcp_sock,udp_sock):
        bridge_signal = False
        tcp_clnt,tcp_host,tcp_port = tcp_sock
        udp_clnt,udp_host,udp_port = udp_sock
        logging.info('Client Bridge Connection Success...')

        try:
            udp_clnt.sendto('client',(udp_host,udp_port))
            while not bridge_signal:
                udp_data,udp_addr = udp_clnt.recvfrom(buffsize)
                if udp_data == 'client_ack_success':
                    bridge_signal = True
            logging.info('Client Bridge Recieved Signal...')

            udp_recvd_thread = threading.Thread(target=self.udp_recvd, args=(tcp_clnt, udp_clnt, udp_host, udp_port))
            udp_recvd_thread.daemon = True
            udp_recvd_thread.start()

            # init TCP connection
            tcp_clnt.connect((tcp_host,tcp_port))

            tcp_recvd_thread = threading.Thread(target=self.tcp_recvd, args=(tcp_clnt, udp_clnt, udp_host, udp_port))
            tcp_recvd_thread.daemon = True
            tcp_recvd_thread.start()

            while self.bridge_flag:
                pass

        except socket.error as msg:
            logging.error(msg)
        except Exception, e:
            raise e
            logging.info(e)
        finally:
            tcp_clnt.close()
            udp_clnt.close()
            logging.info('connection destory success...')

    def tcp_recvd(self, tcp_clnt, udp_clnt, udp_host, udp_port):
        while True:
            tcp_data = tcp_clnt.recv(buffsize)
            if not tcp_data:
                self.bridge_flag = False
            udp_clnt.sendto(tcp_data,(udp_host,udp_port))

    def udp_recvd(self, tcp_clnt, udp_clnt, udp_host, udp_port):
        while True:
            udp_data,udp_addr = udp_clnt.recvfrom(buffsize)
            if not udp_data:
                self.bridge_flag = False
            tcp_clnt.send(udp_data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="rtcp2udp v 1.0 ( Reverse TCP Port to UDP Forwarding Tools )")
    parser.add_argument("-t","--tcp",metavar="",required=True,help="forwarding tcp ipaddress : tcp_port")
    parser.add_argument("-u","--udp",metavar="",required=True,help="connect udp server ipaddress : udp_port")
    args = parser.parse_args()

    if ":" not in args.tcp or ":" not in args.udp:
        logging.info('args is error')
        logging.info('usage: python rtcp2udp -t 172.168.1.10:80 -u 119.29.29.29:53')
        sys.exit(1)

    tcp_addr,tcp_port = args.tcp.split(':')
    udp_addr,udp_port = args.udp.split(':')

    portmap = PortMap()
    tcp_conn = portmap.tcp_client(tcp_addr,int(tcp_port))
    udp_conn = portmap.udp_client(udp_addr,int(udp_port))

    try:
        portmap.udp_forward(tcp_conn,udp_conn)
    except KeyboardInterrupt:
        print "Ctrl C - Stopping Client"
        sys.exit(1)