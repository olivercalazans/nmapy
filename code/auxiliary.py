# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
This file contains classes that are used by many other classes and
data that are essential for all. They are included to avoid code 
repetition and to streamline processes.
"""


import argparse, os, socket, struct, fcntl, ipaddress
from scapy.all import get_if_list, get_if_addr



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



class Argument_Parser_Manager: # =============================================================================
    """This class builds the argument parser for all command classes."""

    def __init__(self) -> None:
        """
        Initializes the Argument Parser Manager.
        This constructor sets up the main argument parser and initializes 
        the subparsers for handling different command classes.
        """
        self._parser = argparse.ArgumentParser(description="Argument Manager")
        self._subparser = self._parser.add_subparsers(dest="class")
        self._argument_class = Argument_Definitions()
        self._add_all_commands()


    def _add_arguments(self, class_name:str, argument_list:list[dict]) -> None:
        """Adds arguments and flags for a specific command class to the parser."""
        class_parser = self._subparser.add_parser(class_name)
        for arg in argument_list:
            match arg[0]:
                case 'bool':  class_parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
                case 'value': class_parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
                case 'opt':   class_parser.add_argument(arg[1], arg[2], nargs='?', const=True, default=False, help=arg[3])
                case _:       class_parser.add_argument(arg[1], type=str, help=arg[2])


    def _add_all_commands(self) -> None:
        """Reads all argument definitions from the Argument_Definitions class and adds them to the parser."""
        for method_name in dir(self._argument_class):
            method = getattr(self._argument_class, method_name)
            if callable(method) and method_name.endswith('_arguments'):
                arguments = method()
                self._add_arguments(arguments[0], arguments[1])


    def _parse(self, subparser_id:str, data:list) -> argparse.Namespace:
        """Parses the given data using the specified subparser ID."""
        data.insert(0, subparser_id)
        return self._parser.parse_args(data)





class Argument_Definitions: # ================================================================================
    """This class contains the definitions for all argument parsers used in the application."""

    @staticmethod
    def _get_ip_arguments():
        return "Get_Ip", [("arg", 'host', "Host name")]


    @staticmethod
    def _ip_geolocation_arguments():
        return "GeoIP", [("arg", "ip", "IP or Hostname")]


    @staticmethod
    def _mac_to_device_arguments():
        return "MacToDev", [("arg", "mac", "MAC to be looked up")]


    @staticmethod
    def _netscanner_arguments():
        return "Netscanner", [("bool", "-p", "--ping", "Use ping instead of an ARP packet")]


    @staticmethod
    def _portscanner_arguments():
        return "PortScanner", [
            ("arg",   "host", "Host name"),
            ("bool",  "-v", "--verbose", "Enable verbose output"),
            ("bool",  "-r", "--random-order", "Use the ports in random order"),
            ("value", "-p", "--port", str, "Specify a port to scan"),
            ("value", "-D", "--decoy", int, "Uses decoy method"),
            ("opt",  "-R", "--random-delay", "Add a delay between packet transmissions."),
        ]





class Files: # ===========================================================================================
    """This class reads files to store necessary data, avoiding repetitive data loading."""

    @staticmethod
    def _get_path(file_name:str) -> str:
        """Returns the full path to the specified file in the databases directory."""
        DIRECTORY = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(DIRECTORY, 'databases', file_name)


    @staticmethod
    def _get_mac_list() -> list[dict]:
        """Reads the MAC address list file and returns a dictionary mapping MAC addresses to their manufacturers."""
        mac_dictionary = {}
        with open(Files._get_path('mac_list.txt'), 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                info = line.split('\t')
                mac_dictionary[info[0].strip()]= info[1]
        return mac_dictionary





class Aux: # =================================================================================================
    """This class provides utility methods to format messages for better visibility."""

    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'

    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'

    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'

    @staticmethod
    def orange(message:str) -> str:
        return '\033[38;5;214m' + message + '\033[0m'

    @staticmethod
    def display_unexpected_error(error:str) -> str:
        return Aux.red('Unexpected error') + f'\nERROR: {error}'

    @staticmethod
    def display_error(message:str) -> str:
        return Aux.yellow('ERROR: ') + message

    @staticmethod
    def display_invalid_missing() -> str:
        return Aux.yellow(f'Invalid or missing argument/flag. Please, check --help')
