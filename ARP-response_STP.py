#!/usr/bin/env python

from scapy.all import *

arppacket=Ether(dst="00:d8:61:d9:87:4d", src="00:d8:61:d9:87:83")/ARP(op=2, 
    hwlen=6,
    plen=4,
    hwdst="00:d8:61:d9:87:83", 
    pdst="172.20.8.168", 
    hwsrc="00:d8:61:d9:87:4d", 
    psrc="172.20.8.160")/Raw() #arp reply to host 172.20.8.168

while len(arppacket) < 64: #adding payload before packet length less then 64 bytes
    arppacket.add_payload('\x00')

arppacket.show2()

print "ARP reply length:", len(arppacket), "bytes.\n" 



stpacket=Ether(dst="01:80:c2:00:00:00")/Dot1Q(prio=4)/LLC(dsap=0x42, ssap=0x42, ctrl=0x03)/STP()/Raw() #STP destination address, LLC field values for STP, STP header 

while len(stpacket) < 120: #adding payload before packet length less then 120 bytes
    stpacket.getlayer(Raw).load+='\x00'

stpacket.show()

print "STP packet length:", len(stpacket), "bytes.\n" 
