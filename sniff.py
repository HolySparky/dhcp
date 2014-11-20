#!/usr/bin/python
# Michael Brown <michael@supermathie.net>

# idea stolen from http://trac.secdev.org/scapy/wiki/IdentifyingRogueDHCPServers

from __future__ import print_function
from scapy.all import *

import sys

# Turn off response IP address validation
conf.checkIPaddr = False

# Set up the interface
#fam,hw = get_if_raw_hwaddr(conf.iface)

#dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
#dhcp_discover =  Ether(src=hw,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])

#VM eth1
#dhcp_discover =  Ether(src=hw,dst="0a:00:27:00:00:00")/IP(src="0.0.0.0",dst="192.168.56.2")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])


#broadcast
#dhcp_discover =  Ether(src=hw,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])


#Localhost 8067
#dhcp_discover =  Ether(src=hw,dst="00:00:00:00:00:00")/IP(src="0.0.0.0",dst="202.120.32.22")/UDP(sport=68,dport=8067)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

#IP packet rather than ethernet packet
dhcp_discover =  IP(dst="202.120.32.22")/UDP(sport=68,dport=8067)/BOOTP(chaddr="e4:ce:8f:32:80:90")/DHCP(options=[("message-type","discover"),"end"])
dhcp_discover.show()
#print("Press Ctrl-C after several seconds...", fd=sys.stderr)
#ans, unans = srp(dhcp_discover, multi=True, timeout=5)
send(dhcp_discover)
print("packets sent")
a = sniff(filter="port 68 or port 67", count=1)
a.summary()

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
