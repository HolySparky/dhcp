#! /usr/bin/env python2
# Test code for Packing DHCP Packet
 
from struct import pack
from scapy.all import *
 
# Initializing
conf.checkIPaddr = False
 
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
 
	def build_disc(self):
		# Build DHCP Discovery Packet
		self.dhcp_disc = Ether(src = self.hw, dst = "ff:ff:ff:ff:ff:ff")/
			         IP(src = "0.0.0.0", dst = "255.255.255.255")/
            		         UDP(sport = 68, dport = 67)/
            		         BOOTP(chaddr = self.hw)/
            		         DHCP(options = [("message-type", "discover"), "end"])
 
		# Setting Xid for DHCP Discovery Packet
		self.dhcp_disc[BOOTP].xid = 123456 
 
		return self.dhcp_disc
 
	def build_req(self):
		# Build DHCP Request Packet
		self.dhcp_request = Ether(src = self.hw, dst = "ff:ff:ff:ff:ff:ff")/
				    IP(src = "0.0.0.0", dst = "255.255.255.255")/
			            UDP(sport = 68, dport = 67)/
				    BOOTP(chaddr = self.hw)/
				    DHCP(options = [("message-type", "request")])
 
		return self.dhcp_disc
 
	def run(self):
		dhcp_disc = self.build_disc()
 
		dhcp_request = self.build_req()
 
		ans_for_disc, unans_for_disc = srp(dhcp_disc)
 
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
			dhcp_request[DHCP].options.append(("hostname", "Dell Laptop E5400"))
			dhcp_request[DHCP].options.append(("param_req_list", b'x01x1c�2x03x0fx06x77x0cx2cx2fx1ax79x2a'))
			dhcp_request[DHCP].options.append("end")
 
		# Setting Xid for DHCP Request Packet, Xid should be same with DHCP Discovery Packet
		dhcp_request[BOOTP].xid = 123456
		ans_for_req, unans_for_req = srp(dhcp_request)
 
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