from abc import ABC, abstractmethod
import argparse
from network import *


class Strategy(ABC): # ===============================================================

    @abstractmethod
    def execute(self, arguments=None):
        pass



class Command_List_Strategy(Strategy): # ============================================
    def execute(self, arguments:str):
        commands = (
            'pscan...: Portscan',
            'ip......: Get IP by name'
        )
        for i in commands: print(i)


class Portscan_Strategy(Strategy): # ================================================
    def execute(self, data:list):
        self._check_if_the_infomation_is_valid(data)
    

    def _check_if_the_infomation_is_valid(self, data:list) -> None:
        try:   argument, flags = self._get_argument_and_flags(data)
        except Exception as error: print(f'Error with the infomation:\nERROR: {error}')
        else:  self._prepare_infomation_to_execute(argument, flags)


    @staticmethod
    def _get_argument_and_flags(data:list) -> tuple[str, dict]:
        parser = argparse.ArgumentParser(description='Portscan of an IP/Host')
        parser.add_argument('argument', type=str, help='Host name')
        parser.add_argument('-p', '--port', type=int, help='Especify a port to scan')
        options = parser.parse_args(data)
        return (options.argument, options.port)
    

    def _prepare_infomation_to_execute(self, argument:str, port:int) -> None:
        port_dictionary = self._get_ports()
        if port is not None and port not in port_dictionary: port_dictionary = {port: 'Generic port'}
        elif port in port_dictionary: port_dictionary = {port: port_dictionary[port]}
        self._get_result(argument, port_dictionary)


    @staticmethod
    def _get_ports() -> dict:
        PORTS = { 
            21  : 'FTP - File Transfer Protocol',  
            22  : 'SSH - Secure Shell',  
            23  : 'Telnet',  
            25  : 'SMTP - Simple Mail Transfer Protocol',   
            53  : 'DNS - Domain Name System', 
            80  : 'HTTP - HyperText Transfer Protocol', 
            110 : 'POP3 - Post Office Protocol version 3', 
            443 : 'HTTPS - HTTP Protocol over TLS/SSL', 
            5432: 'PostgreSQL database system', 
            8080: 'Jakarta Tomcat'
        }
        return PORTS


    @staticmethod
    def _get_result(arguments:str, ports:dict) -> None:
        Network._portscan(arguments, ports)


class IP_Strategy(Strategy): # =====================================================
    def execute(self, arguments:str):
        result = Network._ip(arguments)
        return result
