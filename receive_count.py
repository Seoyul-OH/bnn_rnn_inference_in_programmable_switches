#!/usr/bin/env python

import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers 
from scapy.all import Packet, IPOption
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from time import sleep
import argparse


parser = argparse.ArgumentParser(description='send entry packet')
parser.add_argument('--i', required=False, type=str, default='veth2', help='i')
a = parser.parse_args()
global count
global wrong
global total
count = 0
wrong = 0
total = 0
tos_count = 0

def handle_pkt(pkt):
    global count
    global wrong
    global total
    global tos_count

    if(IP in pkt):
        if (pkt[IP].tos == 1):
            tos_count = tos_count + 1
            if(pkt[IP].src == "10.20.30.40"):
                count = count + 1
            
        elif(pkt[IP].tos == 0):
            if(pkt[IP].src == "10.20.30.40"):
                wrong = wrong + 1
        
    total = count + wrong
    if(total != 0):
        recall = float(count)/float(total)
    else:
        recall = 0

    print("total : {}, tos_count : {}, right : {}, wrong : {}, recall rate : {}".format(total,tos_count,count,wrong,recall))
    # print("right : ", count) # true posiive
    # print("right : ", wrong) # false negative
    # print("recall rate : ", count/total) # true positive / (true positive + false negative)
    


def main():
    
    iface = a.i
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    



if __name__ == '__main__':
    main()


# sudo python receive.py

