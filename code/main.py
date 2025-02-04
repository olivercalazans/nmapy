# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from arg_parser      import Argument_Parser_Manager
from command_list    import Command_List
from sys_command     import System_Command
from port_scanner    import Port_Scanner
from banner_grabbing import Banner_Grabbing
from os_fingerprint  import OS_Fingerprint
from display         import *


class Main: # ================================================================================================

    def __init__(self) -> None:
        self._stop_flag      = False
        self._parser_manager = Argument_Parser_Manager()


    def _handle_user(self) -> None:
        try:   self._loop()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(unexpected_error(error))


    def _loop(self) -> None:
        print("\nFor more information and detailed documentation, please visit the GitHub repository:")
        print("https://github.com/olivercalazans/DataSeeker")
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data         = input('[\033[38;5;202m' + 'DataSeeker' + '\033[0m]# ').split()
            command, arguments = self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists(command, arguments)


    @staticmethod
    def _separates_command_from_arguments(input_data:list) -> tuple[str, list|None]:
        command    = input_data[0]
        arguments  = input_data[1:] or None
        return (command, arguments)


    def _check_if_the_method_exists(self, command:str, arguments:tuple) -> None:
        if command in self._get_strategy_dictionary():
            self._run_command(command, arguments)
        elif command == 'exit':
            self._stop_flag = True
        else:
            print(f'{yellow("Unknown command")} "{command}"')


    def _run_command(self, command:str, arguments:str) -> None:
        try:
            strategy_class = self._get_strategy_dictionary().get(command)
            with strategy_class(self._parser_manager, arguments) as strategy:
                strategy._execute()
        except Exception as error: print(f'{red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _get_strategy_dictionary() -> dict:
        return {
            "help":   Command_List,
            "sys":    System_Command,
            "pscan":  Port_Scanner,
            "banner": Banner_Grabbing,
            "osfing": OS_Fingerprint,
        }




if __name__ == '__main__':
    user = Main()
    user._handle_user()
