#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import hexdump
from kamene.all import *


def send_packet(pkt):
    pkt.show()
    sendp(pkt, iface='veth0')

def main():

    # sniff(offline="/home/p4net/final.pcap", prn=send_packet)
    pkts = rdpcap("pcap/final.pcap")
    iface = "veth0"

    for i in range(1,len(pkts)): # 10~19 (11~20 in wireshark)
        # pkts[i].show()
        try:
            sendp(pkts[i], iface=iface)
            print("packet {} sent.".format(i))
        except OSError:
            print("packet length: ", len(pkts[i]))
        except AttributeError:
            print("Attribute Error")


if __name__ == '__main__':
    main()

