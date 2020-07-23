#!/usr/bin/env python3

import typing
import scapy.all as scapy
from scapy.layers import http


def process_sniffed_packet(packet: scapy.Packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


sniff("eth0")
