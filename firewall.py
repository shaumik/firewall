#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct

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
        ####Loading rules into array
        self.rules = {}
        #print config['rule']
        rule_file = open(config['rule'])
        #rule_file = open("rules.conf")
        rline = rule_file.readline()
        while rline != "":
            rline = rline.lower()
            parsed = rline.split()
            if(len(parsed) != 0):
                if parsed[0] != "%":
                    if parsed[1] not in self.rules:
                        self.rules[parsed[1]] = []
                    self.rules[parsed[1]].append(parsed)
            rline = rule_file.readline()
        rule_file.close()
        #########finished loading rules

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        #####loading geo into array
        geo_file = open("geoipdb.txt")
        line = geo_file.readline()
        self.geoipdb = []
        while line != "":
            line = line.lower()
            self.geoipdb.append(line.split())
            line = geo_file.readline()
        geo_file.close()
        #####finished loading geo
        

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        drop = False
        #print pkt_dir
        #print len(pkt[0:4])
        #print "%d"%(pkt[0:4])
        #print pkt

        l = struct.unpack('!H', pkt[2:4])
        if len(pkt) != l[0]:
            return

        hlen = struct.unpack('!B', pkt[0:1])
        hlen = int(hlen[0]) & 15
        if hlen < 5:
            return
        hlen = hlen*4

        protocol = struct.unpack('!B', pkt[9:10])
        protocol = int(protocol[0])
        print protocol

        if pkt_dir == PKT_DIR_INCOMING:
            source = struct.unpack('!L', pkt[12:16])
            source = source[0]
            if protocol == 17 or protocol == 6:
                srcport = struct.unpack('!H', pkt[hlen:hlen+2])
                srcport = srcport[0]
            if protocol == 1:
                print "ICMP"
            elif protocol == 6:
                print "TCP"
            elif protocol == 17:
                print "UDP"
                drop = self.handle_UDP(source, srcport)
            print drop
            if drop == False:
                self.iface_int.send_ip_packet(pkt)
                print "incoming, send"

        else:
            dest = struct.unpack('!L', pkt[16:20])
            dest = dest[0]
        
            if protocol == 17 or protocol == 6:
                destport = struct.unpack('!H', pkt[hlen+2:hlen+4])
                destport = destport[0]

                if protocol == 1:
                    print "ICMP"
                elif protocol == 6:
                    print "TCP"
                elif protocol == 17:
                    print "UDP"
                    drop = self.handle_UDP(dest, destport)
                print drop

            if drop == False:
                self.iface_ext.send_ip_packet(pkt)
                print "outgoing, send"
        

    def handle_UDP(self, extIP, port):
        drop = False
        for rule in self.rules["udp"]:
            #print rule
            IP = self.ip_conv(extIP)
            ccn = self.geo_search(IP, self.geoipdb)
           # print ccn
            if rule[2] == IP or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 1"
                else:
                    drop = False
            if rule[3] == port or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 2"
                else:
                    drop = False
        #print drop
        return drop
        
    def handle_TCP(self, extIP, port):
        drop = False
        for rule in self.rules["tcp"]:
            #print rule
            IP = self.ip_conv(extIP)
            ccn = self.geo_search(extIP, self.geoipdb)
            #print ccn
            if rule[2] == IP or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 1"
                else:
                    drop = False
            if rule[3] == port or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 2"
                else:
                    drop = False
        #print drop
    def greater_than(ip1,ip2):
        split_ip1 = ip1.split('.')
        split_ip2 = ip2.split('.')
        for i in range(length(split_ip1)):
            if(int(split_ip1[i]) < int(split_ip2[i])):
                return True
        return False

    def geo_search(self, ip, geo):
       # print ip
        if len(geo) <= 1:
            print "failed"
            print "failed"
            return "failed"
        if(geo[len(geo)/2][0] <= ip and geo[len(geo)/2][1] >= ip):
            print ip
            print "found", geo[len(geo)][2]
            return geo[len(geo)][2]
        elif geo[len(geo)/2][0] > ip:
            #print "left"
            print geo[len(geo)/2][0],'>', ip
            return self.geo_search(ip,geo[0:len(geo)/2])
        else:
            #print "right"
            print geo[len(geo)/2][0],'<', ip
            return self.geo_search(ip,geo[len(geo)/2:len(geo)])
        
    def ip_conv(self, extIP):
        first = extIP & 4278190080
        first = first >> 24
        first = str(first)
        second = extIP & 16711680
        second = second >> 16
        second = str(second)
        third = extIP & 65280
        third = third >> 8
        third = str(third)
        fourth = extIP & 255
        fourth = str(fourth)
        result = first + '.' + second + '.' + third + '.' + fourth
        print result 
        print extIP
        return result

    # TODO: You can add more methods as you want.
# TODO: You may want to add more classes/functions as well.
