#!/usr/bin/env python

from scapy.all import *

conf.L3socket=L3RawSocket #using a PF_INET/SOCK_RAW socket instead of a PF_PACKET/SOCK_RAW in order to speak to local applications

s=IP(dst="127.0.0.1")/ICMP()/"Test message" #save echo request to variable
print 'REQUEST:'
s.show2() #parse echo request

r=sr1(s,iface="lo") #send echo request and receive echo reply
print '\nREPLY:'
if r:
    r.show2() #parse echo reply

print 'Verify IP header fields:'
print '    Version IP header is equal to {} as expected (IPv4 default value).'.format(r.version) if r.version == 4 else '    Unexpected value of version IP header: {}'.format(r.version)
print '    The Internet Header Length is equal to {} as expected (smallest value of the IHL field).'.format(r.ihl) if r.ihl == 5 else '    Header length is {} bytes'.format(r.ihl)
print '    Type of service field sets {} as expected.'.format(r.tos) if r.tos == 0 else '    Type of service field sets value {}.'.format(r.tos)
print '    Total length is {} (header length + payload).'.format(r.len)
print '    Time to live field value is {} as expected (loopback request).'.format(r.ttl) if r.ttl == 64 else '    Time to live field value is {}.'.format(r.ttl)
print '    The upper-layer protocol is {} as expected (echo reply).'.format(r.proto) if r.proto == 1 else '    The upper-layer protocol is {}.'.format(r.proto) #the IANA designate value
print '    Source IP is {0}, destination IP is {1}.'.format(r.src, r.dst)

print 'Verify ICMP header:'
print '    Type of ICMP reply is {} as expected (echo reply).'.format(r.type) if r.type == 0 else '    Type of ICMP reply is {} (check ICMP type doc).'.format(r.type)
print '    Code of ICMP reply is {} as expected (no code for success reply).'.format(r.code) if r.code == 0 else '    Code of ICMP reply is {}.'.format(r.code)

print 'Verify sent text:'
print '    Sent raw text is {} as expected.'.format(r.load) if r.load == "Test message" else '    Unexpected text raw text {}.'.format(r.load)
