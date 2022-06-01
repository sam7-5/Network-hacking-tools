#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import signal
import sys
# import netifaces as ni
import time

import scapy.sendrecv
from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether, ARP
from getmac import get_mac_address as gma
import threading

ip_asked = []


def parse_args():
    parser = argparse.ArgumentParser(usage="ArpSpooferDetector.py [-h] [-i IFACE] ",
                                     description="detect arp_spoofing")
    parser.add_argument("-i", "--iface", type=str, help="Interface you wish to use", default="eth0")
    arguments = parser.parse_args()
    return arguments


def empty_ip_asked():
    ip_asked.clear()


def arp_display(pkt):
    flag1 = 0
    flag2 = 0
    print("1packet")
    threading.Timer(0.6, empty_ip_asked).start()  # every 0.6sec empty the is_asked list

    if pkt[ARP].op == 1 and gma() == pkt.hwsrc:  # if broadcast sent by myself we save what ip was asked
        ip_asked.append(pkt.pdst)

    if pkt[ARP].op == 2 and gma() == pkt.hwdst:  # if is-at (response) and sent to me
        # -----first warning----check if someone sends lie about his mac_address
        real_mac = getmacbyip(pkt.psrc)
        received_mac = pkt.hwsrc
        if real_mac != received_mac:
            flag1 = 1
            print("Warning1")

        # -----second warning----check if someone sends me arp_reply that doesn't respond to any request
        if pkt.psrc not in ip_asked:  # check if I asked for this ip
            flag2 = 1
            print("Warning2")

    if flag1 and flag2:
        print("warning arpSpoofing detected!")


if __name__ == "__main__":
    arg = parse_args()
    capture = sniff(filter="arp", prn=arp_display)