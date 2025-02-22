# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random
from scapy.layers.inet import TCP
from scapy.packet      import Packet
from scapy.all         import conf
from arg_parser        import Argument_Manager as ArgParser
from pscan_normal      import Normal_Scan
from pscan_decoy       import Decoy
from network           import *
from display           import *


class Port_Scanner:

    def __init__(self, parser_manager:ArgParser) -> None:
        self._all_ports:dict    = get_ports()
        self._host:str          = None
        self._flags:dict        = None
        self._ports_to_use:list = None
        self._target_ip:str     = None
        self._responses:Packet  = None
        self._my_ip_address:str = None
        self._get_argument_and_flags(parser_manager)


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            self._target_ip = get_ip_by_name(self._host)
            conf.verb       = 0
            self._get_result_by_transmission_method()
            self._process_responses()
        except KeyboardInterrupt:  print(red("Process stopped"))
        except Exception as error: print(unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._host  = parser_manager.host
        self._flags = {
            'show':    parser_manager.show,
            'ports':   parser_manager.port,
            'random':  parser_manager.random,
            'delay':   parser_manager.delay,
            'decoy':   parser_manager.decoy,
        }


    def _prepare_ports(self, specified_ports = None) -> None:
        if specified_ports: 
            self._ports_to_use = [int(valor) for valor in specified_ports.split(",")]
        else:
            self._ports_to_use = list(self._all_ports.keys())

        if self._flags['random']: 
            self._ports_to_use = random.sample(self._ports_to_use, len(self._ports_to_use))


    def _get_result_by_transmission_method(self) -> list:
        if isinstance(self._flags['decoy'], str):
            self._perform_decoy_scan()
        else:
            self._perform_normal_scan()

    
    def _perform_normal_scan(self) -> None:
        self._prepare_ports(self._flags['ports'])
        with Normal_Scan(self._target_ip, self._ports_to_use, self._flags) as SCAN:
            self._responses = SCAN._perform_normal_methods()

    
    def _perform_decoy_scan(self) -> None:
        self._prepare_ports(self._flags['decoy'])
        with Decoy(self._target_ip, self._ports_to_use[0]) as DECOY:
            self._responses     = DECOY._perform_decoy_methods()
            self._flags['show'] = True


    def _process_responses(self) -> None:
        for sent, received in self._responses:
            port           = sent[TCP].dport
            response_flags = received[TCP].flags if received else None
            description    = self._all_ports[port] if port in self._all_ports else 'Generic Port'
            self._display_result(response_flags, port, description)


    def _display_result(self, response:str|None, port:int, description:str) -> None:
        match response:
            case "SA": status = green('Opened')
            case "S":  status = yellow('Potentially Open')
            case "RA": status = red('Closed')
            case "F":  status = red('Connection Closed')
            case "R":  status = red('Reset')
            case None: status = red('Filtered')
            case _:    status = red('Unknown Status')
        if response == 'SA' or self._flags['show']:
            print(f'Status: {status:>17} -> {port:>5} - {description}')