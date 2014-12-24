#! /usr/bin/env python2
# Test code for Packing DHCP Packet
 
from struct import pack
from scapy.all import *
 
# Initializing
conf.checkIPaddr = False
print("------Begin:")

import os
ret = os.system("ifconfig eth0 promisc")
if ret != 0:
    print "______Error: Failed to enable promisc mode on interface, Please run the script with root permission"
    exit()
 
class DHCP_test(object):
    def __init__(self):
        # You may change the value for a special purpose
        self.hw = pack("BBBBBB",0x00, 0x21, 0x9b, 0xe3, 0xae, 0x81)
        self.mac_list = []
        # Define DHCP boot Option fields, for PNR VPN-ID and other: p_i indicates option field i
 	p="\x01\x01\x05\x02\x06\x11\x22\x34\x44\x55\x66" 
	p_5="\x05\x04\x0a\x00\x02\x00"
	p_11="\x0b\x04\xa1\xa2\xa3\xa4"
	p_151="\x97\x08\x01\x01\x02\x03\x04\x05\x06\x07"
	p_152="\x98\x00"
        self.option_string = p_5 + p_11 + p_151 + p_152


    def build_disc(self):
        # Build DHCP Discovery Packet
        self.dhcp_disc = IP(src = "192.168.50.1",
        dst="192.168.50.4")/UDP(sport=68,dport=67)/BOOTP(chaddr=self.hw)/DHCP(options=[("message-type","discover"),("relay_agent_Information",self.option_string),"end"])
        # Setting Xid for DHCP Discovery Packet
        self.dhcp_disc[BOOTP].xid = 123456 
        print("-------disc:")
        self.dhcp_disc.show()
        return self.dhcp_disc
 
    def build_req(self):
        # Build DHCP Request Packet
        self.dhcp_request = IP(src = "0.0.0.0", dst = "192.168.50.4")/UDP(sport = 68, dport = 67)/BOOTP(chaddr = self.hw)/DHCP(options = [("message-type", "request"),("relay_agent_Information",self.option_string)])
        print("--------req:")
        self.dhcp_request.show()
        return self.dhcp_request
 
    def run(self):
        dhcp_disc = self.build_disc()
        dhcp_request = self.build_req()
        ans_for_disc, unans_for_disc = sr(dhcp_disc)
        print("----------------------------------packet disc sent")
        # Finding DHCP Offer Packet
        for offer in ans_for_disc:
            # Print Bootstrap Packet
            print "______Bootstrap Packet______"
            print "Your IP Address is " + str(offer[1][BOOTP].yiaddr)
            print "Gateway IP Address is " + str(offer[1][BOOTP].giaddr)
            # Print the DHCP Offer Packet
            length = len(offer[1][DHCP].options)
            print "______DHCP Options______"
            for op in range(0, length-1):
                print str(offer[1][DHCP].options[op][0]) + ": " + str(offer[1][DHCP].options[op][1])
                if offer[1][DHCP].options[op][0] == 'server_id':
                    server_id = offer[1][DHCP].options[op][1] 
 
            # Modified the DHCP Request Packet
            dhcp_request[DHCP].options.append(("requested_addr", str(offer[1][BOOTP].yiaddr)))
            dhcp_request[DHCP].options.append(("server_id", str(server_id)))
            dhcp_request[DHCP].options.append(("hostname", "Test"))
            dhcp_request[DHCP].options.append(("param_req_list", b'x01x1cx02x03x0fx06x77x0cx2cx2fx1ax79x2a'))
            dhcp_request[DHCP].options.append("end")
 
        # Setting Xid for DHCP Request Packet, Xid should be same with DHCP Discovery Packet
        dhcp_request[BOOTP].xid = 123456
        #ans_for_req, unans_for_req = srp(dhcp_request)
        #ans_for_req, unans_for_req = sr(dhcp_request)
 
        # Print the Ack packet, but currently it has some problem
        for ack in ans_for_req:
            # Print DHCP ACK Packet
            print "______DHCP Options______"
            length = len(ack[1][DHCP].options)
            for op in range(0, length-1):
                print str(ack[1][DHCP].options[op][0]) + ": " + str(ack[1][DHCP].options[op][1])
 
class Testing(object):
    test = DHCP_test()
    test.run()
