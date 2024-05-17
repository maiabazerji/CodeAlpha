import time

import netifaces
import psutil
import scapy.all
from colorama import Fore, Style
from prettytable import PrettyTable
from scapy.all import packet


# input mac, interface name and interface list
def get_interface_name(mac_: str, interface_name_: str, interface_list_: list) -> str:
    mac_ = "-".join(mac_.lower().split(":"))
    interface_list_ = interface_list_[interface_name_]
    for interface in interface_list_:
        if interface.address.lower() == mac_:
            return interface_name_


# print table with interface, mac and ip addresses
def ip_table():
    addrs_names = psutil.net_if_addrs()
    addrs = netifaces.interfaces()

    t = PrettyTable(
        [f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"]
    )

    for interface, psutil_interface_name in zip(addrs, addrs_names):
        mac = netifaces.ifaddresses(interface)
        ip = netifaces.ifaddresses(interface)

        mac_address = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
        interface_name = get_interface_name(
            mac_=mac_address,
            interface_name_=psutil_interface_name,
            interface_list_=addrs_names,
        )

        if netifaces.AF_LINK in mac and netifaces.AF_INET in ip:
            t.add_row(
                [
                    interface_name,
                    mac[netifaces.AF_LINK][0]["addr"],
                    ip[netifaces.AF_INET][0]["addr"],
                ]
            )
        elif netifaces.AF_LINK in mac:
            t.add_row(
                [
                    interface_name,
                    mac[netifaces.AF_LINK][0]["addr"],
                    f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}",
                ]
            )
        elif netifaces.AF_INET in ip:
            t.add_row(
                [
                    interface_name,
                    f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}",
                    ip[netifaces.AF_INET][0]["addr"],
                ]
            )

    print(t)


# sniff packets on the network for 10s
def sniff_all(interface):
    # Initialize the PrettyTable for packet display
    packet_table = PrettyTable()
    packet_table.field_names = [
        "#",
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Length",
    ]

    # Counter for packet numbering
    packet_number = 1

    # process sniffed packets and add them to the table
    def process_sniffed_packet(packet):
        nonlocal packet_number

        # Initialize variables to store packet details
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        source = ""
        destination = ""
        protocol = ""
        length = len(packet)

        # Check if the packet has the Ethernet layer
        if scapy.all.Ether in packet:
            source = packet[scapy.all.Ether].src
            destination = packet[scapy.all.Ether].dst

        # Check if the packet has the IP layer
        if scapy.all.IP in packet:
            source = packet[scapy.all.IP].src
            destination = packet[scapy.all.IP].dst
            protocol = packet[scapy.all.IP].proto

        # Add packet details to the table
        packet_table.add_row(
            [packet_number, timestamp, source, destination, protocol, length]
        )

        # Increment packet number
        packet_number += 1

    # Sniff packets for 10 seconds
    scapy.all.sniff(
        iface=interface, prn=process_sniffed_packet, store=False, timeout=10
    )

    # Print the packet table
    print(packet_table)


def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(
        f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}"
    )
    try:
        choice = "Y"
        ip_table()
        interface = "Wi-Fi"
        print("[*] Sniffing Packets for 10 seconds...")
        sniff_all(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)


main_sniff()
