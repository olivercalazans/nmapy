# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys, argparse
from arg_parser import Argument_Parser_Manager
from pscan      import Port_Scanner
from bgrab      import Banner_Grabbing
from os_fing    import OS_Fingerprint
from display    import *


class Main:

    def __init__(self) -> None:
        self._command_list = {
            "pscan":  Port_Scanner,
            "banner": Banner_Grabbing,
            "osfing": OS_Fingerprint,
        }


    def _handle_user(self) -> None:
        try:   self._validate_input()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(unexpected_error(error))

    
    def _validate_input(self) -> None:
        parser = argparse.ArgumentParser(description="DataSeeker CLI tool")
        parser.add_argument("command", type=str, help="Command name")
        args, remaining_args = parser.parse_known_args()
        if args.command not in self._command_list:
            print(f'{yellow("Unknown command")} "{args.command}"')
        else:
            self._run_command(args.command, remaining_args)


    def _run_command(self, command:str, remainig_args:list) -> None:
        try:
            strategy_class = self._command_list.get(command)
            arg_parser     = Argument_Parser_Manager()
            with strategy_class(arg_parser, remainig_args) as strategy:
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
