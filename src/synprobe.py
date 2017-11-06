#! /usr/bin/env python

from scapy.layers.inet import ICMP, sr, IP, TCP, sr1, RandShort, conf

import sys


dst_ports = [7, 22, 25, 53, 80, 156, 443] # A list containing various well known ports (in event that "-p" is not used)
ip = "0.0.0.0"

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

    checkhost()

    for port in dst_ports:
        if scanport(port) is True:
            print("Port " + str(port) + ": open")


def checkhost():
    global ip
    conf.verb = 0
    try:
        ping = sr(IP(dst = ip)/ICMP())
        print "TARGET IS UP"
    except Exception:
        print "TARGET IS DOWN"


def scanport(port):
    global ip
    conf.verb = 0
    src_port = RandShort()
    SYNACK_packet = sr1(IP(dst = ip)/TCP(sport = src_port, dport = port, flags = "S"), timeout=1)
    #print type(SYNACK_packet)
    if SYNACK_packet is not None:
        pktflags = SYNACK_packet.getlayer(TCP).flags

        if pktflags == 0x12:
            SYNACK_packet.show()
            RSTpkt = sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R"), timeout=1)
            return True
        elif pktflags == 0x14:
            return False
    else:
        return False



main()