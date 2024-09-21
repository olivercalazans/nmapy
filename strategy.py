from abc import ABC, abstractmethod

class Strategy(ABC):
    @abstractmethod
    def execute(self, server, arguments=None):
        pass


class Command_List_Strategy(Strategy):
    def execute(self, server, client_port:int, arguments:str):
        result = server._get_command_list()
        return ('svc', result)


class Portscan_Strategy(Strategy):
    def execute(self, server, client_port:int, arguments:str):
        result = server._portscan(arguments)
        return ('svc', result)
    

class IP_Strategy(Strategy):
    def execute(self, server, client_port:int, arguments:str):
        result = server._ip(arguments)
        return ('svc', result)
