#!/usr/bin/env python

'''Simple script to grep for networks (net + wildcard, subnetmask or CIDR) containing a given IP address.

   Copyright 2013, Steffen Imhof
   Licensed under the MIT License (MIT), see LICENSE file for details

'''

import socket, struct, sys, re, fileinput
from optparse import OptionParser


PORT_NAMES = {
    "bgp": "179",
    "chargen": "19",
    "cmd": "514",
    "daytime": "13",
    "discard": "9",
    "domain": "53",
    "drip": "3949",
    "echo": "7",
    "exec": "512",
    "finger": "79",
    "ftp": "21",
    "ftp-data": "20",
    "gopher": "70",
    "hostname": "101",
    "ident": "113",
    "irc": "194",
    "klogin": "543",
    "kshell": "544",
    "login": "513",
    "lpd": "515",
    "nntp": "119",
    "pim-auto-rp": "496",
    "pop2": "109",
    "pop3": "110",
    "smtp": "25",
    "sunrpc": "111",
    "syslog": "514",
    "tacacs": "49",
    "talk": "517",
    "telnet": "23",
    "time": "37",
    "uucp": "540",
    "whois": "43",
    "www": "80",
    "onep-plain": "15001",
    "onep-tls": "15001",
    "aol ": "5190",
    "bgp ": "179",
    "chargen ": "19",
    "citrix-ica ": "1494",
    "cmd ": "514",
    "ctiqbe ": "2748",
    "daytime ": "13",
    "exec ": "512",
    "finger ": "79",
    "ftp ": "21",
    "ftp-data ": "20",
    "gopher ": "70",
    "https ": "443",
    "h323 ": "1720",
    "hostname ": "101",
    "ident ": "113",
    "imap4 ": "143",
    "irc ": "194",
    "klogin ": "543",
    "kshell ": "544",
    "ldap ": "389",
    "ldaps ": "636",
    "lpd ": "515",
    "login ": "513",
    "lotusnotes ": "1352",
    "netbios-ssn ": "139",
    "nntp ": "119",
    "pcanywhere-data ": "5631",
    "pop2 ": "109",
    "pop3 ": "110",
    "pptp ": "1723",
    "smtp ": "25",
    "sqlnet ": "1521",
    "ssh ": "22",
    "telnet ": "23",
    "uucp ": "540",
    "whois ": "43",
    "www ": "80",
    "discard ": "9",
    "domain ": "53",
    "echo ": "7",
    "kerberos ": "750",
    "pim-auto-rp ": "496",
    "sunrpc (rpc) ": "111",
    "tacacs ": "49",
    "talk ": "517",
    "biff ": "512",
    "bootpc ": "68",
    "bootps ": "67",
    "dnsix ": "195",
    "isakmp ": "500",
    "mobile-ip ": "434",
    "nameserver ": "42",
    "netbios-ns ": "137",
    "netbios-dgm ": "138",
    "ntp ": "123",
    "pcanywhere-status ": "5632",
    "radius ": "1645",
    "radius-acct ": "1646",
    "rip ": "520",
    "secureid-udp ": "5510",
    "snmp ": "161",
    "snmptrap ": "162",
    "syslog ": "514",
    "tftp ": "69",
    "time ": "37",
    "who ": "513",
    "xdmcp ": "177",
    "discard ": "9",
    "domain ": "53",
    "echo ": "7",
    "kerberos ": "750",
    "pim-auto-rp ": "496",
    "sunrpc (rpc) ": "111",
    "tacacs ": "49",
    "talk ": "517",
    "biff": "512",
    "bootpc": "68",
    "bootps": "67",
    "discard": "9",
    "dnsix": "195",
    "domain": "53",
    "echo": "7",
    "isakmp": "500",
    "mobile-ip": "434",
    "nameserver": "42",
    "netbios-dgm": "138",
    "netbios-ns": "137",
    "netbios-ss": "139",
    "non500-isakmp": "4500",
    "ntp": "123",
    "pim-auto-rp": "496",
    "rip": "520",
    "snmp": "161",
    "snmptrap": "162",
    "sunrpc": "111",
    "syslog": "514",
    "tacacs": "49",
    "talk": "517",
    "tftp": "69",
    "time": "37",
    "who": "513",
    "xdmcp": "177"
}


class ACLParser:
    """Helper class to parse an ACL file line by line.
       This will find out protocol, networks and ports for each line and keeps track
       of the name of the current ACL rule."""
    source_net = None
    source_port = None
    destination_net = None
    destination_port = None
    protocol = None

    # Add special patterns to detect IP networks and hosts here
    # Make sure they start with the most specific, as they are tried in order
    net_patterns = [
        r"host\D+(\d+\.\d+\.\d+\.\d+)",
        r"\D(\d+\.\d+\.\d+\.\d+\D\d+\.\d+\.\d+\.\d+)",
        r"\D(\d+\.\d+\.\d+\.\d+\/\d+)",
        r"\s(any)",
    ]

    # Add special patterns to detect port descriptions here
    # Make sure they start with the most specific, as they are tried in order
    port_patterns = [
        r"\s(range\s+\d+\s+\d+)",
        r"\s(n?eq\s(\d+(\s|$))+)",
        r"\s(n?eq\s+\S+)",
        r"\s(gt\s+\d+)",
        r"\s(lt\s+\d+)",
        r"\s(any)",
    ]

    protocol_patterns = [
        r"\s(icmp|ip|tcp|udp)\s"
    ]

    def __init__(self):
        # compile all patterns to regexes
        self.net_patterns = [re.compile(p) for p in self.net_patterns]
        self.port_patterns = [re.compile(p) for p in self.port_patterns]
        self.protocol_patterns = [re.compile(p) for p in self.protocol_patterns]

        # prepare port name map regex (see https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch01s19.html)
        self.port_names = re.compile("\\b" + "\\b|\\b".join(map(re.escape, PORT_NAMES)) + "\\b")

    def reset_transients(self):
        self.source_net = None
        self.source_port = None
        self.destination_net = None
        self.destination_port = None
        self.protocol = None

    def match_patterns(self, line, patterns):
        """We might get invalid matches, e.g. "source_mask destination_net. This gets sorted out by taking
           the first and the last match later on."""
        hits = {}
        for p in patterns:
            m = p.search(line)
            while m:
                if not m.start() in hits:
                    hits[m.start()] = m.group(1)
                m = p.search(line, m.start() + 1)
        return hits

    def assign_source_dest(self, hits, line):
        """Take the first and last one to weed out the invalid hits."""
        result = [None, None]
        sorted_keys = sorted(hits.keys())
        if len(sorted_keys) > 0:
            result[0] = hits[sorted_keys[0]].strip()
        if len(sorted_keys) > 1:
            result[1] = hits[sorted_keys[-1]].strip()

        # if there is only one hit, we must decide whether it is source or destination
        # This should only happen for ports, so let's see if it is at the end of the line
        # (should be destination then)
        if len(sorted_keys) == 1:
            hit = hits[sorted_keys[0]]
            if line.index(hit) + len(hit) > len(line) - 4:

                result[1] = result[0]
                result[0] = None
        return result

    def next_line(self, line):
        self.reset_transients()

        # transform named ports to numbers (see https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch01s19.html)
        line = self.port_names.sub(lambda match: PORT_NAMES[match.group(0)], line)

        # first look for all net matches
        hits = self.match_patterns(line, self.net_patterns)
        (self.source_net, self.destination_net) = self.assign_source_dest(hits, line)

        # transform simple hosts into CIDR form
        if self.source_net and not "any" in self.source_net and not "/" in self.source_net and not " " in self.source_net:
            self.source_net += "/32"
        if self.destination_net and not "any" in self.destination_net and not "/" in self.destination_net and not " " in self.destination_net:
            self.destination_net += "/32"

        # second look for all port matches
        hits = self.match_patterns(line, self.port_patterns)
        (self.source_port, self.destination_port) = self.assign_source_dest(hits, line)

        # look for all protocol matches
        hits = self.match_patterns(line, self.protocol_patterns)
        if len(hits) == 1:
            self.protocol = hits.popitem()[1]

class ACLGrepper:
    '''The main class which handles the grep process as a whole.'''
    splitter = re.compile(r"[^0-9.]")

    parser = ACLParser()

    source_ip_string = None
    source_ip_address = None
    source_port = None

    destination_ip_string = None
    destination_ip_address = None
    destination_port = None

    protocol = None
    match_any = False


    def __init__(self, sip = None, sport = None, dip = None, dport = None, protocol = None, match_any = None):
        self.source_ip_string = sip
        if sip:
            self.source_ip_address = self.ip_to_bits(sip)
        self.source_port = sport

        self.destination_ip_string = dip
        if dip:
            self.destination_ip_address = self.ip_to_bits(dip)
        self.destination_port = dport

        self.protocol = protocol
        self.match_any = match_any

    def ip_to_bits(self, address):
        '''Turns an IP address in dot notation into a single long value.'''

        # Fixup IP addresses with leading zeros
        fixed_address = ".".join([str(int(x)) for x in address.split(".")])

        try:
            return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
        except socket.error:
            raise ValueError("Invalid IP address")

    def ip_in_net(self, ip, net):
        '''Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
           All values are given as longs.'''
        return (net[0] & net[1] == ip & net[1])

    def ip_and_mask_to_pair(self, pattern):
        '''Takes a mask pattern and creates a pair (net address, subnetmask) from it.
           Detects automatically if the mask is a subnetmask or a wildcard mask, assuming the bits are
           set continuously in either.'''
        parts = re.split(self.splitter, pattern)
        net = self.ip_to_bits(parts[0])
        net_or_wildcard = self.ip_to_bits(parts[1])

        # special case full bits -> subnet mask
        if 0xffffffff == net_or_wildcard:
            return (net, 0xffffffff)

        # check if the mask is really a mask (only set bits from the right or left)
        if net_or_wildcard & (net_or_wildcard + 1) != 0:
            net_or_wildcard = 0xffffffff ^ net_or_wildcard
            if net_or_wildcard & (net_or_wildcard + 1) != 0:
                # it's not, never match
                return (0, 0xffffffff)

        return (net, 0xffffffff ^ net_or_wildcard)

    def ip_and_cidr_to_pair(self, pattern):
        '''Takes a CIDR pattern and creates a pair (net address, subnetmask) from it.'''
        parts = pattern.split("/")
        net = self.ip_to_bits(parts[0])
        wildcard = (1 << (32-int(parts[1])))-1
        return (net, 0xffffffff ^ wildcard)

    def net_string_to_pair(self, pattern):
        if pattern.find("/") == -1:
            return self.ip_and_mask_to_pair(pattern)
        else:
            return self.ip_and_cidr_to_pair(pattern)


    def grep(self, line):
        self.parser.next_line(line)

        # FIXME check any if desired
        if self.source_ip_address:
            if self.parser.source_net == "any":
                return self.match_any
            if not self.parser.source_net:
                return False
            if not self.ip_in_net(self.source_ip_address, self.net_string_to_pair(self.parser.source_net)):
                return False

        if self.destination_ip_address:
            if self.parser.destination_net == "any":
                return self.match_any
            if not self.parser.destination_net:
                return False
            if not self.ip_in_net(self.destination_ip_address, self.net_string_to_pair(self.parser.destination_net)):
                return False
                
        if self.protocol:
            if not (self.parser.protocol == self.protocol or self.parser.protocol == "ip"):
                return False
                
        if self.source_port:
            pattern = self.parser.source_port
            
            # no source port found in rule
            if not pattern:
                return False

            # any is ok anyway

            # eq
            if pattern[:2] == "eq":
                parts = pattern.split()
                if not self.source_port in parts[1:]:
                    return False

            # neq
            if pattern[:3] == "neq":
                if self.source_port == pattern[4:]:
                    return False

            # gt
            if pattern[:2] == "gt":
                if int(self.source_port) <= int(pattern[3:]):
                    return False

            # lt
            if pattern[:2] == "lt":
                if int(self.source_port) >= int(pattern[3:]):
                    return False

            # range
            if pattern[:5] == "range":
                parts = pattern.split()
                if int(self.source_port) < int(parts[1]) or int(self.source_port) > int(parts[2]):
                    return False

        if self.destination_port:
            pattern = self.parser.destination_port

            # no destination port found in rule
            if not pattern:
                return False

            # any is ok anyway

            # eq
            if pattern[:2] == "eq":
                parts = pattern.split()
                if not self.destination_port in parts[1:]:
                    return False

            # neq
            if pattern[:3] == "neq":
                if self.destination_port == pattern[4:]:
                    return False

            # gt
            if pattern[:2] == "gt":
                if int(self.destination_port) <= int(pattern[3:]):
                    return False

            # lt
            if pattern[:2] == "lt":
                if int(self.destination_port) >= int(pattern[3:]):
                    return False

            # range
            if pattern[:5] == "range":
                parts = pattern.split()
                if int(self.destination_port) < int(parts[1]) or int(self.destination_port) > int(parts[2]):
                    return False

        return True


if __name__ == '__main__':
    # check command line args
    parser = OptionParser(usage="Usage: %prog [options] [file, file, ...]")
    parser.add_option("-a", "--any", dest="match_any", action="store_true", default=False, help="Match ACLs with 'any', too")
    parser.add_option("-i", "--sip", dest="source_ip", default=None, help="Source IP to look for")
    parser.add_option("-p", "--sport", dest="source_port", default=None, help="Source port to look for")
    parser.add_option("-I", "--dip", dest="destination_ip", default=None, help="Destination IP to look for")
    parser.add_option("-P", "--dport", dest="destination_port", default=None, help="Destination port to look for")
    parser.add_option("-o", "--proto", dest="protocol", default=None, help="Protocol to look for")

    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    # initialize grepper and...
    grepper = ACLGrepper(options.source_ip, options.source_port, options.destination_ip, options.destination_port, options.protocol, options.match_any)

    # ...check all lines in all files (or stdin)
    for line in fileinput.input(args):
        if grepper.grep(line):
            print(line.strip())
