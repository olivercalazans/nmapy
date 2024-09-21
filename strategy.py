from abc import ABC, abstractmethod
from network import *

class Strategy(ABC):
    @abstractmethod
    def execute(self, server, arguments=None):
        pass


class Command_List_Strategy(Strategy):
    def execute(self, arguments:str):
        result = server._get_command_list()
        return ('svc', result)


class Portscan_Strategy(Strategy):
    def execute(self, arguments:str):
        result = Network._portscan(arguments)
        return ('svc', result)
    

class IP_Strategy(Strategy):
    def execute(self, arguments:str):
        result = Network._ip(arguments)
        return ('svc', result)
