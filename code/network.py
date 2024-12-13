# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import psutil, socket, ipaddress
from scapy.all import Packet, Ether, ARP, IP, TCP, UDP, ICMP
from scapy.all import sr1, sr, send, srp
from auxiliary import Color


class Network:
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_network_information(ip:str, subnet_mask:str) -> ipaddress.IPv4Address:
        """Returns the network information for a given IP address and subnet mask."""
        return ipaddress.IPv4Network(f'{ip}/{subnet_mask}', strict=False)


    # IP ADDRESS -----------------------------------------------------------------------------------
    @staticmethod
    def _convert_mask_to_cidr_ipv4(subnet_mask:str) -> int:
        """Converts a subnet mask to CIDR (Classless Inter-Domain Routing) notation."""
        return ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen


    @staticmethod
    def _get_ip_and_subnet_mask(interface:str) -> tuple[str,str]:
        """ Retrieves the IP address and subnet mask for a specified network interface."""
        iface_addresses = psutil.net_if_addrs()[interface]
        net_info = [(address.address, address.netmask) for address in iface_addresses if address.family == socket.AF_INET]
        return {'ip': net_info[0][0], 'netmask': net_info[0][1]}


    @staticmethod
    def _get_ip_by_name(hostname:str, select:bool) -> str:
        """Get the IP address of a given hostname."""
        try:    
            result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ip     = [ip[-1][0] for ip in result]
            if len(ip) == 1:
                ip = ip[0]
            elif select:
                ip = Network._select_an_ip(ip)
        except: ip = Color.display_error(f'Invalid hostname ({hostname})')
        return  ip


    @staticmethod
    def _select_an_ip(ip_list:str) -> str:
        """Selects an IP address from a list by displaying the available options and validating the user's input."""
        Network._display_ips(ip_list)
        ip_list = Network._validate_input(ip_list)
        return ip_list


    @staticmethod
    def _display_ips(ip_list:list[str]) -> None:
        """Displays a list of IP addresses with an index number for each, allowing users to select an IP."""
        for index, ip in enumerate(ip_list):
            print(f'{index} - {ip}')


    # INTERFACES ---------------------------------------------------------------------------------------------
    @staticmethod
    def _select_interface() -> str:
        """Selects a network interface by retrieving available interfaces, displaying them, and validating the user's input."""
        Network._display_interfaces()
        interface_list = [iface for iface in list(psutil.net_if_addrs().keys()) if psutil.net_if_stats()[iface].isup]
        interface      = Network._validate_input(interface_list)
        return interface


    @staticmethod
    def _display_interfaces() -> None:
        """Displays the available network interfaces along with their IP addresses and subnet masks in CIDR notation."""
        interfaces = [iface for iface in Network._get_interface_information() if iface['status'] == 'UP']
        for index, iface in enumerate(interfaces):
            print(f'{index} - {iface["iface"]:<6} => {Color.pink(iface["addr"])}/{Network._convert_mask_to_cidr_ipv4(iface["mask"])}')


    @staticmethod
    def _get_interface_information() -> dict:
        """Retrieves network interface information for the local machine."""
        interface_information = list()
        for iface_name, iface_addresses in psutil.net_if_addrs().items():
            status    = 'UP' if psutil.net_if_stats()[iface_name].isup else'DOWN'
            interface = {'iface': iface_name, 'status': status}
            for address in iface_addresses:
                if address.family == socket.AF_INET: interface.update({'addr': address.address, 'mask': address.netmask, 'broad': address.broadcast})
            interface_information.append(interface)
        return interface_information


    # PACKETS ------------------------------------------------------------------------------------------------
    @staticmethod
    def _create_tpc_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
        """Creates a TCP packet encapsulated in an IP packet with a SYN flag."""
        return IP(src=source_ip, dst=target_ip) / TCP(dport=port, flags="S")


    @staticmethod
    def _create_udp_ip_packet(target_ip:str, port:int, source_ip=None) -> Packet:
        """Creates a UDP packet encapsulated in an IP packet."""
        return IP(src=source_ip, dst=target_ip, ttl=64) / UDP(dport=port)


    @staticmethod
    def _create_icmp_ip_packet(target_ip:str) -> Packet:
        """Creates an ICMP packet encapsulated in an IP packet."""
        return IP(dst=target_ip) / ICMP()


    @staticmethod
    def _create_arp_packet(network) -> Packet:
        """Creates an ARP request packet to be sent over the network."""
        return ARP(pdst=str(network)) / Ether(dst="ff:ff:ff:ff:ff:ff")


    # SENDING METHODS ---------------------------------------------------------------------------------------
    @staticmethod
    def _send_and_receive_single_layer3_packet(packet:Packet) -> Packet|None:
        """Sends a single packet at the network layer (Layer 3) and waits for a response."""
        return sr1(packet, timeout=3, verbose=0)


    @staticmethod
    def _send_and_receive_multiple_layer3_packets(packets:Packet, interval=0.1) -> list[Packet]:
        """Sends multiple packets at the network layer (Layer 3) and waits for responses."""
        answered, _ = sr(packets, timeout=5, inter=interval, verbose=0)
        return answered


    @staticmethod
    def _send_a_single_layer3_packet(packet:Packet) -> None:
        """Sends a single packet at the network layer (Layer 3) without waiting for a response."""
        send(packet, verbose=0)


    @staticmethod
    def _send_and_receive_layer2_packet(packet:Ether) -> list:
        """Sends a packet at the data link layer (Layer 2) and waits for a response."""
        answered, _ = srp(packet, timeout=2, verbose=False)
        return answered


    # PORTS -------------------------------------------------------------------------------------------------
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


    # GENERAL -----------------------------------------------------------------------------------------------
    @staticmethod
    def _validate_input(options:list[str]) -> str:
        """Prompts the user to select an option from a list and validates the input."""
        while True:
            try:
                number = int(input('Choose one: '))
                if number >= 0 and number < len(options):
                    return options[number]
                else:
                    print(Color.yellow(f'Choose a number between 0 and {len(options) - 1}'))
            except: print(Color.yellow('Choose a number'))
