import os, platform
from strategy import *

class Main:
    DIRECTORY = os.path.dirname(os.path.abspath(__file__))
    if platform.system() == 'Windows': DIRECTORY += '\\wfiles\\'
    elif platform.system() == 'Linux': DIRECTORY += '/wfiles/'


    STRATEGY_DICTIONARY = {
        "help":  Command_List_Strategy(),
        "pscan": Portscan_Strategy(),
        "ip":    IP_Strategy()
    }


    def __init__(self) -> None:
        self._stop_flag = False
        self._create_directory(self._get_directory())


    @staticmethod
    def _create_directory(directory:str) -> None:
        try:   os.mkdir(directory)
        except FileExistsError: print('The directory already exists')
        except Exception as error: print(f'Error creating directory: {error}')
        else:  print('Directory created')


    @classmethod
    def _get_directory(cls) -> str:
        return cls.DIRECTORY
    

    @classmethod
    def _get_strategy_dictionary(cls) -> dict:
        return cls.STRATEGY_DICTIONARY


    @property
    def stop(self) -> None:
        self._stop_flag = True


    def _handle_user(self) -> None:
        try:   self._loop()
        except Exception as error: print(f'Error: {error}') 


    def _loop(self) -> None:
        while not self._stop_flag:
            print('Write "help" to see the commands ' + '=' * 20)
            input_data = input('> ')
            command = self._separate_command_key_from_arguments(input_data)
            result  = self._check_if_the_method_exists(command)
            for line in result: print(line)


    @staticmethod
    def _separate_command_key_from_arguments(input_data:str) -> str:
        command = input_data.split(' ')
        return command[0]


    def _check_if_the_method_exists(self, command:str) -> str:
        if command in self._get_strategy_dictionary():
            result = self._get_result(command)
        else:
            result = 'Invalid command'
        return result


    def _get_result(self, command:str, arguments:str = None) -> str:
        strategy = self._get_strategy_dictionary().get(command)
        return strategy.execute(arguments)
       



if __name__ == '__main__':
    user = Main()
    user._handle_user()
