import os
import pyfiglet
from strategy import *
from network import *

class Main(Network_MixIn):
    STRATEGY_DICTIONARY = {
        "help":  Command_List_Strategy(),
        "pscan": Portscan_Strategy(),
        "ip":    IP_Strategy()
    }


    def __init__(self) -> None:
        self._stop_flag    = False
        self._command_list = (
            'pscan - Portscan',
            'ip - Get IP by name'
        )


    @property
    def stop(self):
        self._stop_flag = True
        

    def _handle_client(self) -> None:
        while not self._stop_flag:



    @staticmethod
    def _separate_function_from_arguments(string:str) -> tuple[str, str]:
        ...


    def _check_if_the_method_exists(self) -> tuple[str, str]:
        ...


    def _get_result(self) -> tuple[str, str]:
       ...


    @classmethod
    def _get_strategy_dictionary(cls) -> dict:
        return cls.STRATEGY_DICTIONARY


if __name__ == '__main__':
    server = Main()
    server.receive_client()
