from abc import ABC, abstractmethod
import argparse, os, platform
from network import *


class Strategy(ABC): # ---------------------------------------------------------------
    DIRECTORY = os.path.dirname(os.path.abspath(__file__))
    if platform.system() == 'Windows': DIRECTORY += '\\wfiles\\'
    elif platform.system() == 'Linux': DIRECTORY += '/wfiles/'

    @abstractmethod
    def execute(self, arguments=None):
        pass


    @classmethod
    def _get_directory(cls) -> str:
        return cls.DIRECTORY
    

    @staticmethod
    def _create_directory() -> None:
        try:   os.mkdir(Strategy._get_directory())
        except FileExistsError: print('The directory already exists')
        except Exception as error: print(f'Error creating directory: {error}')
        else:  print('Directory created')


    @staticmethod
    def _write_file(file_name, data):
        with open(Strategy._get_directory() + file_name, 'wb') as file:
            for line in data:
                file.write(line)



class Command_List_Strategy(Strategy): # --------------------------------------------
    def execute(self, arguments:str = None):
        return (
            'pscan...: Portscan',
            'ip......: Get IP by name'
        )



class Portscan_Strategy(Strategy): # ------------------------------------------------
    @staticmethod
    def _ports() -> dict:
        ports = { 
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
        return ports


    def execute(self, arguments:str):
        parser = argparse.ArgumentParser()
        result = Network._portscan(arguments)
        return result
    

class IP_Strategy(Strategy):
    def execute(self, arguments:str):
        result = Network._ip(arguments)
        return result
