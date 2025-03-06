# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse


class Argument_Manager:

    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser(description="Argument Manager")

    
    # Method that will be called by the class
    def _parse(self, command:str, arguments:list) -> argparse.Namespace:
        self._create_arguments(command)
        return self._parser.parse_args(arguments)
            

    def _create_arguments(self, command:str) -> None:
        for arg in self._argument_definitions(command):
            match arg[0]:
                case 'bool':  self._parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
                case 'value': self._parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
                case 'opt':   self._parser.add_argument(arg[1], arg[2], nargs='?', const=True, default=False, help=arg[3])
                case 'arg':   self._parser.add_argument(arg[1], type=str, help=arg[2])
                case _:       self._parser.add_argument(arg[1], type=str, choices=arg[2], help=arg[3])
    

    @staticmethod
    def _argument_definitions(command:str) -> dict:
        PROTOCOLS   = ['ftp', 'ssh', 'http', 'https']
        DEFINITIONS = {
            'pscan': [
                ('arg',   'host', 'Target IP/Hostname'),
                ('bool',  '-s', '--show',    'Display all statuses, both open and closed'),
                ('bool',  '-r', '--random',  'Use the ports in random order'),
                ('value', '-p', '--port',    str, 'Specify a port to scan'),
                ('bool',  '-a', '--all',     'Scan all ports'),
                ('opt',   '-d', '--delay',   'Add a delay between packet transmissions'),
                ('bool',  '-S', '--stealth', 'Use only one packet with "SYN" flag'),
                ('value', '-D', '--decoy',   str, 'Uses decoy method'),
                ],
            
            'banner': [
                ('arg',    'host',     'Target IP/Hostname'),
                ('choice', 'protocol', PROTOCOLS, 'Protocol'),
                ('value',  '-p', '--port', str, 'Specify a port to grab the banners')
                ],

            'netmap': [
                ('bool', '-p', '--ping', 'Use ping instead of an ARP packet')
                ]
        }
        return DEFINITIONS[command]