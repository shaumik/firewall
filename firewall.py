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
        #print protocol

        if pkt_dir == PKT_DIR_INCOMING:
            #print "INCOMING"
            source = struct.unpack('!L', pkt[12:16])
            source = source[0]
            if protocol == 17 or protocol == 6:
                srcport = struct.unpack('!H', pkt[hlen:hlen+2])
                srcport = srcport[0]
            if protocol == 1:
                print "ICMP"
                typez = struct.unpack('!B', pkt[hlen:hlen+1])
                drop = self.handle_ICMP(source, typez)
            elif protocol == 6:
                #print "TCP"
                drop = self.handle_TCP(source, srcport)
            elif protocol == 17:
                print "UDP"
                drop = self.handle_UDP(source, srcport)
            if drop == False:
                self.iface_int.send_ip_packet(pkt)
                #print "incoming, send"

        else:
            #print "OUTGOING"
            dest = struct.unpack('!L', pkt[16:20])
            dest = dest[0]
            if protocol == 17 or protocol == 6:
                destport = struct.unpack('!H', pkt[hlen+2:hlen+4])
                destport = destport[0]

                if protocol == 1:
                    print "ICMP"
                    typez = struct.unpack('!B', pkt[hlen:hlen+1])
                    drop = self.handle_ICMP(dest, typez)
                elif protocol == 6:
                    # print "TCP"
                    drop = self.handle_TCP(dest, destport)
                elif protocol == 17:
                    print "UDP"
                    #h2len = struct.unpack('!H', pkt[hlen+4:hlen+6])
                    #print hlen
                    #print h2len
                    #h2len = int(h2len[0]) + hlen
                    #print h2len
                    h2len = hlen + 8
                    if destport == 53:
                        print "DNS FOR LIFE"
                        drop = self.handle_DNS(h2len, pkt, dest, destport)
                        print "drop or no?", drop
                    else:
                        drop = self.handle_UDP(dest, destport)
                        print "this is udp"
                        print "drop or no?", drop

            if drop == False:
                #print "drop is False so I'm sending!!!!"
                self.iface_ext.send_ip_packet(pkt)
                #print "outgoing, send"
        
    def decoder(self, s):
        i = 0
        sz = ""
        while s[i] != chr(6):
            i += 1
        i = i+1
        while s[i] != chr(3):
            sz += s[i]
            i += 1
        sz += '.'
        i += 1
        while s[i] != chr(3) or s[i] != 0:
            sz += s[i]
            i += 1
            if i == len(s):
                break
        return sz

    def handle_DNS(self, h2len, pkt, extIP, port):
        done = False
        QDCount = struct.unpack('!H', pkt[h2len+4:h2len+6])
        QDCount = int(QDCount[0])
        if QDCount != 1:
            return self.handle_UDP(extIP, port)
        Qtype = struct.unpack('!H', pkt[-4:-2])[0]
        if Qtype != 1 and Qtype != 28:
            print "not A and not AAAA", Qtype
            return self.handle_UDP(extIP, port)
        Qclass = struct.unpack('!H', pkt[-2:])[0]
        if Qclass != 1:
            print "not internet"
            return self.handle_UDP(extIP, port)
        
        print "inside handle DNS"
        Qname = ""
        ch = struct.unpack('!B', pkt[h2len+12:h2len+12+1])[0]
        x = pkt[h2len+12:]
        i = 1
        #print pkt[h2len+12:h2len+12+1]
        while ch != 0:
            print "ch", ch
            #print "Qname", Qname
            for k in range(ch):
                
                Qname += chr(struct.unpack('!B', pkt[h2len+12+i+k:h2len+12+1+i+k])[0])
                print 'k', k
                print "Qname", Qname
                #i += 1
            i += ch
            ch = struct.unpack('!B', pkt[h2len+12+i:h2len+12+1+i])[0]
            if ch != 0:
                Qname += '.'
            i += 1
        print "Qname:", Qname
        split_domain = Qname.split('.')
        domain = split_domain[-2] + '.' + split_domain[-1]
        print "domain after split", domain
        #domain = self.decoder(Qname)
        #print "Domain:", self.decoder(Qname)
        split_domain.reverse()
        if 'www' in split_domain:
            split_domain.remove('www')
        for rule in self.rules["dns"]:
            print "rule", rule
            dns_list = rule[2].split('.')
            dns_list.reverse()
            print "dns_list is rule", dns_list
            print "test", split_domain
            k = 0
            match = True
            if len(dns_list) != len(split_domain) and dns_list[-1] != '*':
                match = False
                print "lengths are different and no wildcard", match
                continue
            else:
                while k < min(len(dns_list), len(split_domain)):
                    if dns_list[k] == '*':
                        print "wild card"
                        match = True
                        break
                    if dns_list[k] != split_domain[k]:
                        print "mismatch"
                        match = False
                        break
                    k += 1
            if match == True:                
                if rule[0] == "drop":
                    print "drop time"
                    done = True
                elif rule[0] == "pass":
                    print "pass time"
                    done = False
        print "i guess dont drop", done
        return done

    def handle_UDP(self, extIP, port):
        drop = False
        for rule in self.rules["udp"]:
            #print rule
            IP = self.ip_conv(extIP)
            ccn = self.geo_search(IP, self.geoipdb)
           # print ccn
            if rule[2] == IP or rule[2] == 'any' or rule[2] == ccn:
                if rule[0] == 'drop': 
                    drop = True
                    #print "gonna drop 1"
                else:
                    drop = False
            if rule[3] == port or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    #print "gonna drop 2"
                else:
                    drop = False
        #print drop
        return drop
        
    def handle_TCP(self, extIP, port):
        drop = False
        for rule in self.rules["tcp"]:
            #print rule
            IP = self.ip_conv(extIP)
            ccn = self.geo_search(IP, self.geoipdb)
           # print ccn
            if rule[2] == IP or rule[2] == 'any' or rule[2] == ccn:
                if rule[0] == 'drop': 
                    drop = True
                    #print "gonna drop 1"
                else:
                    drop = False
            if rule[3] == port or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    #print "gonna drop 2"
                else:
                    drop = False
        #print drop
        return drop

    def handle_ICMP(self, extIP, type):
        drop = False
        for rule in self.rules["icmp"]:
            #print rule
            IP = self.ip_conv(extIP)
            ccn = self.geo_search(IP, self.geoipdb)
           # print ccn
            if rule[2] == IP or rule[2] == 'any' or rule[2] == ccn:
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 1"
                else:
                    drop = False
            if rule[3] == type or rule[2] == 'any':
                if rule[0] == 'drop': 
                    drop = True
                    print "gonna drop 2"
                else:
                    drop = False
        #print drop
        return drop

    def greater_than(self,ip1,ip2):
        if ip1 == ip2:
            return True
        split_ip1 = ip1.split('.')
        split_ip2 = ip2.split('.')
        for i in range(len(split_ip1)):
            if(int(split_ip1[i]) > int(split_ip2[i])):
                return True
            elif(int(split_ip1[i]) < int(split_ip2[i])):
                return False

    def geo_search(self, ip, geo):
       # print ip
        if len(geo) <= 1:
            #print "failed"
            #print "failed"
            return "failed"
        if self.greater_than(ip, geo[len(geo)/2][0]) and self.greater_than(geo[len(geo)/2][1], ip):
        #if(geo[len(geo)/2][0] <= ip and geo[len(geo)/2][1] >= ip):
            #print ip
            #print geo[len(geo)/2]
            #print "found", geo[len(geo)/2][2]
            return geo[len(geo)/2][2]
        elif self.greater_than(geo[len(geo)/2][0], ip):
        #elif geo[len(geo)/2][0] > ip:
            #print "left"
            #print geo[len(geo)/2][0],'>', ip
            return self.geo_search(ip,geo[0:len(geo)/2])
        else:
            #print "right"
            #rint geo[len(geo)/2][0],'<', ip
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
        #print result 
        #print extIP
        return result

    # TODO: You can add more methods as you want.
# TODO: You may want to add more classes/functions as well.
