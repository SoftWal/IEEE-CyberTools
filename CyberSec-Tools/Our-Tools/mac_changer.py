
import subprocess
import optparse
import re

#function
def main():
    dual = mac_arguments()
    current_mac(dual.interface)
    change_mac(dual.interface, dual.mac)
    current_mac(dual.interface)


# Get the argument from the usr
def mac_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface", dest="interface", help="Target Interface")
    parser.add_option("-m","--mac", dest="mac", help="Changes Mac")
    (options, argument) = parser.parse_args()
    if not options.interface:
        parser.error("Please input a valid interface")
    elif not options.mac:
        parser.error("Please input a mac address")
    return options


# This is where what makes the mac changer possible
def change_mac(interface, mac):
    print("Changing Mac Adress of "+ interface + " to " + mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig",interface,"hw","ether",mac])
    subprocess.call(["ifconfig", interface, "up"])

# Gets the current mac for the interface
def current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_adress_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    print("Your Mac Adress Was " + mac_adress_search_result.group(0))

main()


