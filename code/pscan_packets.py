# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.layers.l2   import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet      import Packet


def create_tpc_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
    return IP(src=source_ip, dst=target_ip) / TCP(dport=port, flags="S")


def create_udp_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
    return IP(src=source_ip, dst=target_ip, ttl=64) / UDP(dport=port)


def create_icmp_ip_packet(target_ip:str) -> Packet:
    return IP(dst=target_ip) / ICMP()


def create_arp_packet(network) -> Packet:
    return ARP(pdst=str(network)) / Ether(dst="ff:ff:ff:ff:ff:ff")