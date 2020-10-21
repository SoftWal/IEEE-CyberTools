#!/usr/bin/env python

import scapy.all as scapy

# Scanning the network function
from pip._vendor.distlib.compat import raw_input


def scan(ip):
    answered_client = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip))[0]
    client_list = []
    for elements in answered_client:
        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list

# End of the scan

# Prints the results
def print_result(results_list):
    print("IP\t\t\t Mac Address\n---------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# End of printing function

scan_result = scan(str(raw_input("Enter IP Range ")))
print_result(scan_result)