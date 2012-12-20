#!/usr/bin/env python

'''Simple script to grep for networks (net + wildcard, subnetmask or CIDR) containing a given IP address.'''

import socket, struct, sys, re, fileinput

# Configuration
# Add special patterns to detect IP networks here
cidr_patterns = [
	r"\D(\d+\.\d+\.\d+\.\d+\/\d+)\D",
]

mask_patterns = [
	r"\D(\d+\.\d+\.\d+\.\d+\D\d+\.\d+\.\d+\.\d+)\D",
]

splitter = re.compile(r"[^0-9.]")


def bit_print_pair(numbers):
	'''Prints the given numbers as 32 digit binary.'''
	print bin(numbers[0])[2:].rjust(32,'0'), bin(numbers[1])[2:].rjust(32,'0')

def ip_to_bits(address):
	'''Turns an IP address in dot notation into a single long value.'''
	
	# Fixup IP addresses with leading zeros
	fixed_address = ".".join([str(int(x)) for x in address.split(".")])
	
	return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
	
def ip_in_net(ip, net):
	'''Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
	   All values are given as longs.'''
	return (net[0] & net[1] == ip_address & net[1])

def ip_and_mask_to_pair(pattern):
	'''Takes a mask pattern and creates a pair (net address, subnetmask) from it.
	   Detects automatically if the mask is a subnetmask or a wildcard mask, assuming the bits are
	   set continuously in either.'''
	parts = re.split(splitter, pattern)
	net = ip_to_bits(parts[0])
	net_or_wildcard = ip_to_bits(parts[1])
	
	# special case full bits -> wildcard mask
	if 0xffffffff == net_or_wildcard:
		return (net, 0xffffffff)

	# check if the mask is really a mask (only set bits from the right or left)
	if net_or_wildcard & (net_or_wildcard + 1) != 0:
		net_or_wildcard = 0xffffffff ^ net_or_wildcard
		if net_or_wildcard & (net_or_wildcard + 1) != 0:
			# it's not, never match
			return (0, 0xffffffff)

	return (net, 0xffffffff ^ net_or_wildcard)

def ip_and_cidr_to_pair(pattern):
	'''Takes a CIDR pattern and creates a pair (net address, subnetmask) from it.'''
	parts = pattern.split("/")
	net = ip_to_bits(parts[0])
	wildcard = (1 << (32-int(parts[1])))-1
	return (net, 0xffffffff ^ wildcard)

def tests():
	'''Run a few tests.'''
	bit_print_pair(ip_and_mask_to_pair("192.168.2.0 255.255.255.0"))
	bit_print_pair(ip_and_mask_to_pair("192.168.2.0/255.255.255.0"))
	bit_print_pair(ip_and_mask_to_pair("192.168.2.0 0.0.0.255"))
	bit_print_pair(ip_and_mask_to_pair("192.168.2.0 255.255.252.0"))
	bit_print_pair(ip_and_mask_to_pair("10.0.0.0 255.0.0.0"))

	bit_print_pair(ip_and_cidr_to_pair("192.168.2.0/24"))
	bit_print_pair(ip_and_cidr_to_pair("192.168.2.0/22"))
	bit_print_pair(ip_and_cidr_to_pair("10.0.0.0/8"))

# check command line args
if len(sys.argv) == 2 and sys.argv[1] == "test":
	tests()
	exit()

if len(sys.argv) < 2:
	print "USAGE: aclgrep.py ip_adress file [, file, file, ...]"
	exit()

ip_address = ip_to_bits(sys.argv[1])

# compile all patterns to regexes
mask_patterns = [ re.compile(p) for p in mask_patterns ]
cidr_patterns = [ re.compile(p) for p in cidr_patterns ]

# check all lines in all files (or stdin)
for line in fileinput.input(sys.argv[2:]):
	line_has_matched = False
	for p in mask_patterns:
		m = p.search(line)
		while m:
			line_has_matched = True
			net = ip_and_mask_to_pair(m.group(1))
			if ip_in_net(ip_address, net):
				print fileinput.filename() + ":" + line,
			m = p.search(line, m.start() + 1)
	
	# prevent CIDR matches if a mask match was already found
	if line_has_matched:
		continue
	
	for p in cidr_patterns:
		m = p.search(line)
		while m:
			net = ip_and_cidr_to_pair(m.group(1))
			if ip_in_net(ip_address,net):
				print fileinput.filename() + ":" + line,
			m = p.search(line, m.start() + 1)
