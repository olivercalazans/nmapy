# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ipaddress, fcntl, struct
from scapy.all import Packet, Ether, ARP, IP, TCP, UDP, ICMP, Raw
from scapy.all import sr1, sr, send, srp
from scapy.all import conf, get_if_addr
from auxiliary import Color


class Network:
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_default_interface() -> str:
        return str(conf.iface)


    @staticmethod
    def _get_ip_address(interface:str) -> str:
        """Get the IP address of the specified network interface."""
        try:   return get_if_addr(interface)
        except Exception: return 'Unknown/error'


    @staticmethod
    def _get_subnet_mask(interface:str) -> str|None:
        """Get the subnet mask of the specified network interface."""
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
        """Returns the network information for a given IP address and subnet mask."""
        return ipaddress.IPv4Network(f'{ip}/{subnet_mask}', strict=False)


    @staticmethod
    def _convert_mask_to_cidr_ipv4(subnet_mask:str) -> int:
        """Converts a subnet mask to CIDR (Classless Inter-Domain Routing) notation."""
        return ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen


    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        """Get the IP address of a given hostname."""
        try:    return socket.gethostbyname(hostname)
        except: return Color.display_error(f'Invalid hostname ({hostname})')


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
    




class OS_Fingerprint_Packets(): # ============================================================================

    @staticmethod
    def _sequence_generation_packets(target_ip:str, open_port:int) -> Packet:
        """ Sequence generation (SEQ, OPS, WIN, and T1) """
        return (
            IP(dst=target_ip) / TCP(dport=open_port, window=1,   options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b''),]),
            IP(dst=target_ip) / TCP(dport=open_port, window=63,  options=[('MSS', 1400),  ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=16,  options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=512, options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))])
        )


    @staticmethod
    def _icmp_echo_packets(target_ip:str) -> Packet:
        """ ICMP echo (IE) """
        return (
            IP(dst=target_ip, tos=0, flags='DF') / ICMP(type=8, code=9, id=12345, seq=295) / Raw(load=b'\x00' * 120),
            IP(dst=target_ip, tos=4)       /       ICMP(type=8, code=0, id=12346, seq=296) / Raw(load=b'\x00' * 150)
            )


    @staticmethod
    def _ecn_syn_packet(target_ip:str, open_port:int) -> Packet:
        """ TCP explicit congestion notification (ECN) """
        TCP_OPTIONS        = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SACKOK', b''), ('NOP', None), ('NOP', None)]
        packet             = IP(dst=target_ip) / TCP(dport=open_port, flags="S", window=3, options=TCP_OPTIONS)
        packet[TCP].flags |= 0x18    # 0x18 = CWR (0b00010000) + ECE (0b00001000)
        return packet


    @staticmethod
    def _t2_through_t7_tcp_packets(target_ip:str, open_port:int, closed_port:int) -> Packet:
        """ TCP (T2–T7) """
        COMMON_TCP_OPTIONS        = [('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')]
        COMMOM_WSCALE_AND_OPTIONS = [('WScale', 10)] + COMMON_TCP_OPTIONS    # Equivalent in hex (03030A0102040109080AFFFFFFFF000000000402)
        return (
            IP(dst=target_ip, flags='DF') / TCP(dport=open_port,   flags='',     window=128,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=open_port,   flags='SFUP', window=256,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip, flags='DF') / TCP(dport=open_port,   flags='A',    window=1024,  options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=closed_port, flags='S',    window=31337, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip, flags='DF') / TCP(dport=closed_port, flags='A',    window=32768, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=closed_port, flags='FPU',  window=65535, options=[('WScale', 15)] + COMMON_TCP_OPTIONS)
        )


    @staticmethod
    def _udp_packet(target_ip:str, closed_port:int) -> Packet:
        """ UDP (U1) """
        packet    = Network._create_udp_ip_packet(target_ip, closed_port)
        packet.id = 0x1042
        packet    = packet / Raw(load=b'C' * 300)
        return packet