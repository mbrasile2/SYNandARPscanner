#! /usr/bin/env python

from scapy.all import *
import netaddr
import socket
import sys


dst_ports = [7, 22, 25, 53, 80, 156, 443]               # A list containing various well known ports (in event that "-p" is not used)
ip = "0.0.0.0"                                          # The target address (or subnet)

def main():
    global dst_ports, ip

    # This if changes the list of ports if the p flag is set
    if sys.argv[1] == "-p":
        arg_port = str(sys.argv[2]).split("-")
        dst_ports = []

        if len(arg_port) > 1:
            for port in range(int(arg_port[0]), int(arg_port[1]) + 1):
                 dst_ports.append(port)
        else:
            dst_ports.append(int(arg_port[0]))
        ip = str(sys.argv[3])
    else:
        ip = str(sys.argv[1])

    if '/' in ip:                                       # ip represents a subnet
        network = netaddr.IPNetwork(ip)
    else:
        network = [ip]

    for host in network:
        if checkhost(host):                             # Check if host is up
            for port in dst_ports:                      # Scan through all of the ports
                scanport(port, host)       # Port is open


def checkhost(host):
    conf.verb = 0
    try:
        ping = sr(IP(dst = host)/ICMP(), timeout=5)
        return True
    except Exception:
        return False


def scanport(port, host):
    conf.verb = 0
    src_port = RandShort()
    SYNACK_packet = sr1(IP(dst = str(host))/TCP(sport = src_port, dport = port, flags = "S"), timeout=1)
    if SYNACK_packet is not None:
        pktflags = SYNACK_packet.getlayer(TCP).flags

        if pktflags == 0x12:

            ACK_packet = IP(dst=str(host)) / TCP(sport=src_port, dport=port, flags="R")
            send(ACK_packet)

            s = socket.socket()
            s.connect((host, port))
            if port != 22:
                s.sendall("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
            banner = s.recv(1024)
            print("Port " + str(port) + ": open. Response: " + banner)
            s.close()

main()