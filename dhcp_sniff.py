#!/usr/bin/python
# Michael Brown <michael@supermathie.net>

# idea stolen from http://trac.secdev.org/scapy/wiki/IdentifyingRogueDHCPServers

from __future__ import print_function
from scapy.all import *

import sys

# Turn off response IP address validation
conf.checkIPaddr = False

# Set up the interface

conf.iface="en1" #set this as the interface of the server

fam,hw = get_if_raw_hwaddr(conf.iface)

dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

#print("Press Ctrl-C after several seconds...", fd=sys.stderr)
ans, unans = srp(dhcp_discover, multi=True, timeout=5)

if len(ans) == 0:
    print("No DHCP offers received", file=sys.stderr)
else:
    print("DHCP offers received:")
    for pair in ans:
        p = pair[1]
        d = p[DHCP]
        print("MAC: {0}, Server IP: {1}, Offer IP: {2}\n    Mask: {3}, Router: {4}, Domain: {5}".format(
            p[Ether].src,
            p[IP].src,
            p[BOOTP].yiaddr,
            filter(lambda x: x[0] == 'subnet_mask', d.options)[0][1],
            filter(lambda x: x[0] == 'router', d.options)[0][1],
            filter(lambda x: x[0] == 'domain', d.options)[0][1],
            ))
