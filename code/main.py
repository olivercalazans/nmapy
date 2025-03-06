# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/NetXplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from arg_parser import Argument_Manager as ArgParser
from pscan      import Port_Scanner
from bgrab      import Banner_Grabbing
from netmap     import Network_Mapper
from display    import *


class Main:

    def __init__(self) -> None:
        self._command:str    = None
        self._arguments:list = None
        self._commands_dict  = {
            'pscan':  Port_Scanner,
            'banner': Banner_Grabbing,
            'netmap': Network_Mapper
        }


    def _handle_user(self) -> None:
        try:   self._validate_input()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(unexpected_error(error))

    
    def _validate_input(self) -> None:
        try: 
            self._command   = sys.argv[1]
            self._arguments = sys.argv[2:] if len(sys.argv) > 2 else list()
            self._verify_if_the_command_exists()
        except IndexError:
            print(f'{yellow("Missing command name")}')


    def _verify_if_the_command_exists(self) -> None:
        if    self._command in self._commands_dict: self._validate_flags()
        elif  self._command in ('--help', '-h'):    self._display_description()
        else: print(f'{yellow("Unknown command")} "{self._command}"')


    def _validate_flags(self) -> None:
        arg_parser = ArgParser()._parse(self._command, self._arguments)
        self._run_command(arg_parser)


    def _run_command(self, arg_parser:ArgParser) -> None:
        try:
            strategy_class = self._commands_dict.get(self._command)
            with strategy_class(arg_parser) as strategy:
                strategy._execute()
        except Exception as error:
            print(f'{red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _display_description() -> None:
        print('Repository: https://github.com/olivercalazans/DataSeeker\n'
              'DataSeeker CLI is a tool for network exploration\n'
              'Available commands:\n'
              f'{green("pscan")}....: Portscaning\n'
              f'{green("banner")}...: Banner Grabbing\n'
              f'{green("netmap")}...: Network Mapping\n'
              )


if __name__ == '__main__':
    user = Main()
    user._handle_user()
