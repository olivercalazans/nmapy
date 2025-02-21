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
        self._command:str    = None
        self._arguments:list = None
        self._commands_dict  = {
            "pscan":  Port_Scanner,
            "banner": Banner_Grabbing,
            "osfing": OS_Fingerprint
        }


    def _handle_user(self) -> None:
        try:   self._validate_input()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(unexpected_error(error))

    
    def _validate_input(self) -> None:
        parser = argparse.ArgumentParser(description="DataSeeker CLI tool")
        parser.add_argument("command", type=str, help="Command name")
        arg, self._arguments = parser.parse_known_args()
        self._command        = arg.command

        if self._command not in self._commands_dict:
            print(f'{yellow("Unknown command")} "{self._command}"')
        else:
            self._run_command()


    def _run_command(self) -> None:
        try:
            strategy_class = self._commands_dict.get(self._command)
            arg_parser     = Argument_Parser_Manager()._parse(self._command, self._arguments)
            with strategy_class(arg_parser) as strategy:
                strategy._execute()
        except Exception as error: print(f'{red("Error while trying to execute the command")}.\nERROR: {error}')





if __name__ == '__main__':
    user = Main()
    user._handle_user()
