from scapy.all import *
from sys import platform
import netifaces
import sys


interface = ""
conf.verb = 0
entries = {}

# set different default interface for each OS
if platform == "linux" or platform == "linux2":
    interface = "eth0"
elif platform == "darwin":
    interface = "en0"

# Handle optional command line argument
if len(sys.argv) > 1:
    if sys.argv[1] == "-i":
        interface = sys.argv[2]
    else:
        print "Usage arpwatch.py [-i interface]"
        exit(1)


addrs = netifaces.ifaddresses(interface)
my_ip = addrs[netifaces.AF_INET][0]["addr"]
ip_vals = str(my_ip).split(".")

entries[str(my_ip)] = str(addrs[netifaces.AF_LINK][0]["addr"])


src_ip = ip_vals[0] + "." + ip_vals[1] + "." +ip_vals[2] + ".0/24"

# Perform initial ARP scan
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=src_ip), timeout=1, iface=interface,inter=0.1)

print "------INITIAL ARPCACHE IP/MAC ADDRESSES------"

for snd, rcv in ans:
    ip = rcv.sprintf(r"%ARP.psrc%")
    mac = rcv.sprintf(r"%Ether.src%")

    print ip + "\t\t:\t\t" + mac
    entries[ip] = mac


def packet_filter(packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    source_mac = packet.sprintf("%ARP.hwsrc%")

    if source in entries and entries[source] != source_mac:
        print source + " CHANGED FROM " + entries[source] + " TO " + source_mac

print "\n------------BEGINNING PASSIVE SCAN------------"

sniff(filter = "arp", prn = packet_filter, iface=interface, store=0)



