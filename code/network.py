# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, struct, fcntl, ipaddress
from scapy.all import get_if_list, get_if_addr
from auxiliary import Aux


class Network: # =============================================================================================
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_network_interfaces() -> list[str]:
        """Get the device's network interfaces"""
        return get_if_list()


    @staticmethod
    def _select_interface() -> str:
        """Selects a network interface by retrieving available interfaces, displaying them, and validating the user's input."""
        interfaces = Network._get_network_interfaces()
        Network._display_interfaces(interfaces)
        interface  = Network._validate_input(interfaces)
        return interface


    @staticmethod
    def _display_interfaces(interfaces:list) -> None:
        """Displays the available network interfaces along with their IP addresses and subnet masks in CIDR notation."""
        for index, iface in enumerate(interfaces):
            ip_addr = Network._get_ip_address(iface)
            netmask = Network._get_subnet_mask(iface)
            print(f'{index} - {iface} => {ip_addr}/{Network._convert_mask_to_cidr(netmask)}')


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
        return ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)


    @staticmethod
    def _convert_mask_to_cidr(subnet_mask:str) -> int:
        """Converts a subnet mask to CIDR (Classless Inter-Domain Routing) notation."""
        return ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen


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
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
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


    @staticmethod
    def _validate_input(options:list[str]) -> str:
        """Prompts the user to select an option from a list and validates the input."""
        while True:
            try: 
                number = int(input('Choose one: '))
                if number >= 0 and number < len(options):
                    return options[number]
                else:
                    print(Aux.yellow(f'Choose a number between 0 and {len(options) - 1}'))
            except: print(Aux.yellow('Choose a number'))
