from abc import ABC, abstractmethod
from network import *

class Strategy(ABC):
    @abstractmethod
    def execute(self, server, arguments=None):
        pass


class Command_List_Strategy(Strategy):
    def execute(self, arguments:str):
        return (
            'pscan - Portscan',
            'ip - Get IP by name'
        )


class Portscan_Strategy(Strategy):
    def execute(self, arguments:str):
        result = Network._portscan(arguments)
        return result
    

class IP_Strategy(Strategy):
    def execute(self, arguments:str):
        result = Network._ip(arguments)
        return result
