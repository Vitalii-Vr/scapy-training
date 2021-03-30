#!/usr/bin/env python

from scapy.all import *

arppacket=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst='172.20.8.168')/Raw() #arp request to resolve IP 172.20.8.168
print 'ARP REQUEST:'

while len(arppacket) < 64: #adding payload before packet length less then 64 bytes
    arppacket.add_payload('0')

arppacket.show2() #parse arp request

print "ARP request length:", len(arppacket), "bytes.\n" 
results=srp1(arppacket,timeout=2) #send arp request
print '\nARP REPLY:'
results.show2() #parse arp response



print 'UDLD PACKET:'
udldpacket=Ether(dst="01:00:0c:cc:cc:cc", type=0x0111)/Dot1Q(prio=7)/LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)/Raw() #destination MAC and ethertype (HDLC prot type) for UDLD, priority 7, LLC header value for UDLD

while len(udldpacket) < 68: #adding payload before packet length less then 64 bytes
    udldpacket.getlayer(Raw).load+='\x00'

udldpacket.show()

print "UDLD packer length:", len(udldpacket), "bytes.\n" 
