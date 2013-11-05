#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.'
        self.rules = {}
        rule_file = open("rules.conf")
        rline = rule_file.readline()
        while rline != "":
            parsed = rline.split()
            if(len(parsed) != 0):
                if parsed[0] != "%":
                    if parsed[1] not in self.rules:
                        self.rules[parsed[1]] = []
                    self.rules[parsed[1]].append(parsed)
            rline = rule_file.readline()
        rule_file.close()
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.
        geo_file = open("geoipdb.txt")
        line = geo_file.readline()
        self.geoipdb = []
        while line != "":
            self.geoipdb.append(line.split())
            line = geo_file.readline()
        geo_file.close()
        
        
    def geoipdb(self):
        return self.geoipdb

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pass
    
    
    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
