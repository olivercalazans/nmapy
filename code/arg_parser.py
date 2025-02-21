# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse


class Argument_Parser_Manager:

    def __init__(self) -> None:
        self._parser    = argparse.ArgumentParser(description="Argument Manager")
        self._subparser = self._parser.add_subparsers(dest="class")
        self._create_arguments()
            

    def _create_arguments(self) -> None:
        for command_name, argument_list in self._argument_definitions().items():
            class_parser = self._subparser.add_parser(command_name)
            for arg in argument_list:
                match arg[0]:
                    case 'bool':  class_parser.add_argument(arg[1], action="store_true", help=arg[2])
                    case 'value': class_parser.add_argument(arg[1], type=arg[2], help=arg[3])
                    case 'opt':   class_parser.add_argument(arg[1], nargs='?', const=True, default=False, help=arg[2])
                    case 'arg':   class_parser.add_argument(arg[1], type=str, help=arg[2])
                    case _:       class_parser.add_argument(arg[1], type=str, choices=arg[2], help=arg[3])
    

    @staticmethod
    def _argument_definitions() -> dict:
        PROTOCOLS = ['http', 'https', 'ssh']
        return {
            "PortScanner": [
                ("arg",   "host", "Target IP/Hostname"),
                ("bool",  "-r", "Use the ports in random order"),
                ("value", "-p", str, "Specify a port to scan"),
                ("value", "-D", str, "Uses decoy method"),
                ("opt",   "-d", "Add a delay between packet transmissions."),
                ("bool",  "-s", "Display all statuses, both open and closed.")
                ],
            
            "BannerGrabbing": [
                ("arg",    "host",     "Target IP/Hostname"),
                ("choice", "protocol", PROTOCOLS, "Protocol"),
                ("value",  "-p", str, "Specify a port to grab the banners")
                ],

            "OSFingerprint": [
                ("arg", "host", "Target IP/Hostname")
                ]
        }
    

    # Method that will be called by the class
    def _parse(self, subparser_id:str, data:list) -> argparse.Namespace:
        data.insert(0, subparser_id)
        return self._parser.parse_args(data)