# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
This file contains classes that are used by many other classes and
data that are essential for all. They are included to avoid code 
repetition and to streamline processes.
"""


import argparse, os, socket, fcntl, struct
from scapy.all import get_if_list, get_if_addr



class Network: # =============================================================================================
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        """Get the IP address of a given hostname."""
        try:    ip = socket.gethostbyname(hostname)
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
        return  ip
    

    @staticmethod
    def _get_network_interfaces() -> list[str]:
        """Get the device's network interfaces"""
        return get_if_list()
    

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
            if arg[0] == 'bool':
                class_parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
            elif arg[0] == 'value':
                class_parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
            else:
                class_parser.add_argument(arg[1], type=str, help=arg[2])


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
        return "Get_Ip", [
            ("arg", 'host', "Host name")
        ]


    @staticmethod
    def _portscanner_arguments():
        return "PortScanner", [
            ("arg", "host", "Host name"),
            ("value", "-p", "--port", int, "Specify a port to scan"),
            ("value", "-D", "--decoy", int, "Uses decoy method"),
            ("bool", "-v", "--verbose", "Enable verbose output")
        ]
    

    @staticmethod
    def _netscanner_arguments():
        return "Netscanner", [
            ("arg", "ip", "IP"),
            ("bool", "-p", "--ping", "Use ping instead of an ARP package")
        ]
    

    @staticmethod
    def _ip_geolocation_arguments():
        return "GeoIP", [
            ("arg", "ip", "IP or Hostname")
        ]
    

    @staticmethod
    def _mac_to_device_arguments():
        return "MacToDev", [
            ("arg", "mac", "MAC to be looked up")
        ]
    




class DataBases: # ===========================================================================================
    """This class reads files to store necessary data, avoiding repetitive data loading."""

    @staticmethod
    def _get_path(file_name:str) -> str:
        """Returns the full path to the specified file in the databases directory."""
        DIRECTORY = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(DIRECTORY, 'databases', file_name)
    

    def _get_mac_list(self) -> list[dict]:
        """Reads the MAC address list file and returns a dictionary mapping MAC addresses to their manufacturers."""
        mac_dictionary = {}
        with open(self._get_path('mac_list.txt'), 'r', encoding='utf-8') as file:
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
