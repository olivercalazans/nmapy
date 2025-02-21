# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse


class Argument_Parser_Manager:

    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser(description="Argument Manager")

    
    # Method that will be called by the class
    def _parse(self, command:str, arguments:list) -> argparse.Namespace:
        self._create_arguments(command)
        return self._parser.parse_args(arguments)
            

    def _create_arguments(self, command:str) -> None:
        for arg in self._argument_definitions(command):
            match arg[0]:
                case 'bool':  self._parser.add_argument(arg[1], action="store_true", help=arg[2])
                case 'value': self._parser.add_argument(arg[1], type=arg[2], help=arg[3])
                case 'opt':   self._parser.add_argument(arg[1], nargs='?', const=True, default=False, help=arg[2])
                case 'arg':   self._parser.add_argument(arg[1], type=str, help=arg[2])
                case _:       self._parser.add_argument(arg[1], type=str, choices=arg[2], help=arg[3])
    

    @staticmethod
    def _argument_definitions(command:str) -> dict:
        PROTOCOLS   = ['http', 'https', 'ssh']
        DEFINITIONS = {
            "pscan": [
                ("arg",   "host", "Target IP/Hostname"),
                ("bool",  "-r", "Use the ports in random order"),
                ("value", "-p", str, "Specify a port to scan"),
                ("value", "-D", str, "Uses decoy method"),
                ("opt",   "-d", "Add a delay between packet transmissions."),
                ("bool",  "-s", "Display all statuses, both open and closed.")
                ],
            
            "banner": [
                ("arg",    "host",     "Target IP/Hostname"),
                ("choice", "protocol", PROTOCOLS, "Protocol"),
                ("value",  "-p", str, "Specify a port to grab the banners")
                ],

            "osfing": [
                ("arg", "host", "Target IP/Hostname")
                ]
        }
        return DEFINITIONS[command]