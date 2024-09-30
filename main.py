from auxiliary import *
from network import *

class Main:
    def __init__(self) -> None:
        self._stop_flag = False


    @property
    def _stop(self) -> None:
        self._stop_flag = True


    def _handle_user(self) -> None:
        try:   self._loop()
        except Exception as error: print(f'{Aux._red("ERROR")}: {error}')


    def _loop(self) -> None:
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data         = input('>> ').split(' ')
            command, arguments = self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists(command, arguments)


    @staticmethod
    def _separates_command_from_arguments(input_data) -> tuple[str, list]:
        command   = input_data[0]
        arguments = input_data[1:] or [None]
        return (command, arguments)


    def _check_if_the_method_exists(self, command:str, arguments:tuple) -> None:
        if command in self._get_strategy_dictionary():
            self._get_result(command, arguments)
        elif command == 'exit':
            self._stop
        else:
            print(f'{Aux._yellow("Unknown command")} "{command}"')


    def _get_result(self, command:str, arguments:str) -> None:
        strategy = self._get_strategy_dictionary().get(command)
        try:   strategy._execute(arguments)
        except Exception as error: print(f'{Aux._red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _get_strategy_dictionary() -> dict:
        STRATEGY_DICTIONARY = {
            "help":  Command_List(),
            "pscan": Port_Scanner(),
            "ip":    Get_IP()
        }
        return STRATEGY_DICTIONARY


if __name__ == '__main__':
    user = Main()
    user._handle_user()
