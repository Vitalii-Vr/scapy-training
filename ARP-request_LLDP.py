#!/usr/bin/env python

from scapy.all import *

arppacket=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst='172.20.8.168')/Raw() #arp request to resolve IP 172.20.8.168
print 'ARP REQUEST:'

while len(arppacket) < 68: #adding payload before packet length less then 68 bytes
    arppacket.add_payload('\x00')

arppacket.show2() #parse arp request

print "ARP request length:", len(arppacket), "bytes.\n" 

results=srp1(arppacket,timeout=2) #send arp request
print '\nARP REPLY:'
results.show2() #parse arp response



lldppacket=Ether(dst="01:80:c2:00:00:0e", type=0x88cc)/Dot1Q(prio=5)/Raw() #Tagged priority 5, destination MAC for LLDP packet, EtherType for LLDP packet

while len(lldppacket) < 78: #adding payload before packet length less then 78 bytes
    lldppacket.getlayer(Raw).load+='\x00'

lldppacket.show()

print "LLDP packet length:", len(lldppacket), "bytes.\n" 
