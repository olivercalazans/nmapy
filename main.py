import os, platform
from strategy import *

class Main:
    STRATEGY_DICTIONARY = {
        "help":  Command_List_Strategy(),
        "pscan": Portscan_Strategy(),
        "ip":    IP_Strategy()
    }


    def __init__(self) -> None:
        self._stop_flag = False
        Strategy._create_directory()
    

    @classmethod
    def _get_strategy_dictionary(cls) -> dict:
        return cls.STRATEGY_DICTIONARY


    @property
    def _stop(self) -> None:
        self._stop_flag = True


    def _handle_user(self) -> None:
        try:   self._loop()
        except Exception as error: print(f'ERROR: {error}')


    def _loop(self) -> None:
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data         = input('>> ').split(' ')
            command, arguments = self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists(command, arguments)


    @staticmethod
    def _separates_command_from_arguments(input_data) -> tuple[str, tuple]:
        command   = input_data[0]
        arguments = (input_data[1:] + [None])
        return (command, arguments)


    def _check_if_the_method_exists(self, command:str, arguments:tuple) -> None:
        if command in self._get_strategy_dictionary():
            self._get_result(command, arguments)
        elif command == 'exit':
            self._stop
        else:
            print('Invalid command')


    def _get_result(self, command:str, arguments:str) -> None:
        strategy = self._get_strategy_dictionary().get(command)
        try:   strategy.execute(arguments)
        except Exception as error: print(f'Error while trying to call a "execute" method.\nERROR: {error}')



if __name__ == '__main__':
    user = Main()
    user._handle_user()
