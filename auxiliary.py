# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse, os


class Aux: # =================================================================================================
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





class Argument_Parser_Manager: # =============================================================================
    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser(description="Argument Manager")
        self._subparser = self._parser.add_subparsers(dest="class")
        self._argument_class = Argument_Definitions()
        self._add_all_commands()


    def _add_arguments(self, class_name:str, argument_list:list[dict]) -> None:
        class_parser = self._subparser.add_parser(class_name)
        for arg in argument_list:
            if arg[0] == 'bool':
                class_parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
            elif arg[0] == 'value':
                class_parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
            else:
                class_parser.add_argument(arg[1], type=str, help=arg[2])


    def _add_all_commands(self) -> None:
        for method_name in dir(self._argument_class):
            method = getattr(self._argument_class, method_name)
            if callable(method) and method_name.endswith('_arguments'):
                arguments = method()
                self._add_arguments(arguments[0], arguments[1])


    def _parse(self, subparser_id:str, data:list) -> argparse.Namespace:
        data.insert(0, subparser_id)
        return self._parser.parse_args(data)
    




class Argument_Definitions: # ================================================================================
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
            ("bool",  "-v", "--verbose", "Enable verbose output")
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
    @staticmethod
    def _get_path(file_name:str) -> str:
        DIRECTORY = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(DIRECTORY, 'databases', file_name)
    

    def _get_mac_list(self) -> list[dict]:
        mac_dictionary = {}
        with open(self._get_path('oui.txt'), 'r') as file:
            for line in file:
                line = line.strip()
                info = line.split('\t')
                mac_dictionary[info[0].strip()]= info[1]
        return mac_dictionary
