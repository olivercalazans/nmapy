# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
This file contains classes that are used by many other classes and
data that are essential for all. They are included to avoid code 
repetition and to streamline processes.
"""


import argparse



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
                case 'arg':   class_parser.add_argument(arg[1], type=str, help=arg[2])
                case _:       class_parser.add_argument(arg[1], type=str, choices=arg[2], help=arg[3])


    def _parse(self, subparser_id:str, data:list) -> argparse.Namespace:
        """Parses the given data using the specified subparser ID."""
        data.insert(0, subparser_id)
        return self._parser.parse_args(data)





class Argument_Definitions: # ================================================================================
    """This class contains the definitions for all argument parsers used in the application."""

    @staticmethod
    def _sys_command_arguments():
        return "SysCommand", [("arg", "command", "System command")]


    @staticmethod
    def _portscanner_arguments():
        return "PortScanner", [
            ("arg",   "host", "Target IP/Hostname"),
            ("bool",  "-r", "--random-order", "Use the ports in random order"),
            ("value", "-p", "--port",  str, "Specify a port to scan"),
            ("value", "-D", "--decoy", str, "Uses decoy method"),
            ("opt",   "-d", "--delay", "Add a delay between packet transmissions."),
        ]


    @staticmethod
    def _banner_grabbing_arguments():
        PROTOCOLS = ['http', 'https', 'ssh']
        return "BannerGrabbing", [
            ("arg",    "host",     "Target IP/Hostname"),
            ("choice", "protocol", PROTOCOLS, "Protocol"),
            ("value",  "-p", "--port", str, "Specify a port to grab the banners")
        ]


    @staticmethod
    def _os_fingerprint_arguments():
        return "OSFingerprint", [("arg", "host", "Target IP/Hostname")]





class DataBase: # ======================================================================================
    """
    Stores auxiliary data and instances needed for other classes.
    This includes managing argument parsers and storing databases like the MAC dictionary.
    """

    def __init__(self) -> None:
        """Initializes the DataBase class by setting up the argument parser manager and loading necessary data."""
        self._parser_manager   = Argument_Parser_Manager()


    @property
    def parser_manager(self) -> Argument_Parser_Manager:
        """Returns the Argument_Parser_Manager instance for handling argument parsing."""
        return self._parser_manager





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
    def display_unexpected_error(error:str) -> str:
        return Color.red('Unexpected error') + f'\nERROR: {error}'

    @staticmethod
    def display_error(message:str) -> str:
        return Color.yellow('ERROR: ') + message

    @staticmethod
    def display_invalid_missing() -> str:
        return Color.yellow(f'Invalid or missing argument/flag. Please, check --help')