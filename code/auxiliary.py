# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
This file contains classes that are used by many other classes and
data that are essential for all. They are included to avoid code 
repetition and to streamline processes.
"""


import argparse, os



class Argument_Parser_Manager: # =============================================================================
    """This class builds the argument parser for all command classes."""

    def __init__(self) -> None:
        """
        Initializes the Argument Parser Manager.
        This constructor sets up the main argument parser and initializes 
        the subparsers for handling different command classes.
        """
        self._parser         = argparse.ArgumentParser(description="Argument Manager")
        self._subparser      = self._parser.add_subparsers(dest="class")
        self._argument_class = Argument_Definitions()
        self._add_all_commands()


    def _add_all_commands(self) -> None:
        """Reads all argument definitions from the Argument_Definitions class and adds them to the parser."""
        for method_name in dir(self._argument_class):
            method = getattr(self._argument_class, method_name)
            if callable(method) and method_name.endswith('_arguments'):
                arguments = method()
                self._add_arguments(arguments[0], arguments[1])


    def _add_arguments(self, class_name:str, argument_list:list[dict]) -> None:
        """Adds arguments and flags for a specific command class to the parser."""
        class_parser = self._subparser.add_parser(class_name)
        for arg in argument_list:
            match arg[0]:
                case 'bool':  class_parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
                case 'value': class_parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
                case 'opt':   class_parser.add_argument(arg[1], arg[2], nargs='?', const=True, default=False, help=arg[3])
                case _:       class_parser.add_argument(arg[1], type=str, help=arg[2])


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
        return "Netmapper", [("bool", "-p", "--ping", "Use ping instead of an ARP packet")]


    @staticmethod
    def _portscanner_arguments():
        return "PortScanner", [
            ("arg",   "host", "Host name"),
            ("bool",  "-r", "--random-order", "Use the ports in random order"),
            ("value", "-p", "--port", str, "Specify a port to scan"),
            ("value", "-D", "--decoy", str, "Uses decoy method"),
            ("opt",   "-d", "--delay", "Add a delay between packet transmissions."),
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





class Color: # =================================================================================================
    """This class provides utility methods to format messages for better visibility."""
    
    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'
    
    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'

    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'
    
    @staticmethod
    def blue(message:str) -> str:
        return '\033[34m' + message + '\033[0m'

    @staticmethod
    def pink(message:str) -> str:
        return '\033[35m' + message + '\033[0m'

    @staticmethod
    def display_unexpected_error(error:str) -> str:
        return Color.red('Unexpected error') + f'\nERROR: {error}'

    @staticmethod
    def display_error(message:str) -> str:
        return Color.yellow('ERROR: ') + message

    @staticmethod
    def display_invalid_missing() -> str:
        return Color.yellow(f'Invalid or missing argument/flag. Please, check --help')
