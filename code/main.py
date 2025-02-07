# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from arg_parser      import Argument_Parser_Manager
from sys_command     import System_Command
from port_scanner    import Port_Scanner
from banner_grabbing import Banner_Grabbing
from os_fingerprint  import OS_Fingerprint
from display         import *


class Main: # ================================================================================================

    def __init__(self) -> None:
        self._stop_flag      = False
        self._parser_manager = Argument_Parser_Manager()
        self._command        = None
        self._arguments      = None
        self._command_list   = {
            "sys":    System_Command,
            "pscan":  Port_Scanner,
            "banner": Banner_Grabbing,
            "osfing": OS_Fingerprint,
        }


    def _handle_user(self) -> None:
        try:   self._loop()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(unexpected_error(error))


    def _loop(self) -> None:
        print("\nFor more information and detailed documentation, please visit the GitHub repository:")
        print("https://github.com/olivercalazans/DataSeeker")
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data = input('[\033[38;5;202m' + 'DataSeeker' + '\033[0m]# ').split()
            self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists()


    def _separates_command_from_arguments(self, input_data:list) -> None:
        self._command   = input_data[0]
        self._arguments = input_data[1:] or None


    def _check_if_the_method_exists(self) -> None:
        if   self._command in self._command_list: self._run_command()
        elif self._command == 'help': self._display_commands(self._command_list)
        elif self._command == 'exit': self._stop_flag = True
        else: print(f'{yellow("Unknown command")} "{self._command}"')


    def _run_command(self) -> None:
        try:
            strategy_class = self._command_list.get(self._command)
            with strategy_class(self._parser_manager, self._arguments) as strategy:
                strategy._execute()
        except Exception as error: print(f'{red("Error while trying to execute the command")}.\nERROR: {error}')
    

    @staticmethod
    def _display_commands(commands:dict) -> None:
        for key in commands:
            space   = 9 - len(key)
            command = str(commands[key].__name__).replace('_', ' ')
            print(f'{green(key)}{"." * space}: {command}')




if __name__ == '__main__':
    user = Main()
    user._handle_user()
