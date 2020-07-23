#!/usr/bin/env python3

import scapy.all as scapy


def process_sniffed_packet(packet):
    print(packet)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


sniff("eth0")
