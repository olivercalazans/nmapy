# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ipaddress, fcntl, struct
from scapy.layers.l2   import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all         import Packet, conf, get_if_addr
from display           import Display


class Network_Information:

    @staticmethod
    def _get_default_interface() -> str:
        return str(conf.iface)


    @staticmethod
    def _get_ip_address(interface:str) -> str:
        try:   return get_if_addr(interface)
        except Exception: return 'Unknown/error'


    @staticmethod
    def _get_subnet_mask(interface:str) -> str|None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temporary_socket:
                return socket.inet_ntoa(fcntl.ioctl(
                    temporary_socket.fileno(),
                    0x891b,  # SIOCGIFNETMASK
                    struct.pack('256s', interface[:15].encode('utf-8'))
                )[20:24])
        except Exception:
            return None
        

    @staticmethod
    def _get_network_information(ip:str, subnet_mask:str) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Network(f'{ip}/{subnet_mask}', strict=False)


    @staticmethod
    def _convert_mask_to_cidr_ipv4(subnet_mask:str) -> int:
        return ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen


    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        try:    return socket.gethostbyname(hostname)
        except: return Display.error(f'Invalid hostname ({hostname})')

    
    @staticmethod
    def _get_ports() -> dict:
        return { 
            21   : 'FTP - File Transfer Protocol',  
            22   : 'SSH - Secure Shell',  
            23   : 'Telnet',  
            25   : 'SMTP - Simple Mail Transfer Protocol',   
            53   : 'DNS - Domain Name System',
            67   : 'DHCP',
            80   : 'HTTP - HyperText Transfer Protocol', 
            110  : 'POP3 - Post Office Protocol version 3',
            135  : 'msrpc',
            139  : 'Netbios - ssn',
            443  : 'HTTPS - HTTP Protocol over TLS/SSL',
            445  : 'Microsoft - ds',
            3306 : 'MySQL/MariaDB',
            3389 : 'RDP - Remote Desktop Protocol',
            5432 : 'PostgreSQL database system',
            5900 : 'VNC - Virtual Network Computing',
            6379 : 'Redis',
            8080 : 'Jakarta Tomcat',
            2179 : 'vmrdp',
            3389 : 'ms-wbt-server',
            7070 : 'realserver',
            27017: 'MongoDB'
        }





class Packets: # =============================================================================================

    @staticmethod
    def _create_tpc_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
        return IP(src=source_ip, dst=target_ip) / TCP(dport=port, flags="S")


    @staticmethod
    def _create_udp_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
        return IP(src=source_ip, dst=target_ip, ttl=64) / UDP(dport=port)


    @staticmethod
    def _create_icmp_ip_packet(target_ip:str) -> Packet:
        return IP(dst=target_ip) / ICMP()


    @staticmethod
    def _create_arp_packet(network) -> Packet:
        return ARP(pdst=str(network)) / Ether(dst="ff:ff:ff:ff:ff:ff")