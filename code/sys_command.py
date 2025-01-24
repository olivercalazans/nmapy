# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import subprocess
from arg_parser import Argument_Parser_Manager
from display    import Display


class System_Command: # =========================================================================================

    def __init__(self, parser_manager:Argument_Parser_Manager, data:list):
        self._parser_manager = parser_manager
        self._command        = " ".join(data)
    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self):
        try:
            self._get_argument()
            process = subprocess.Popen(self._command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                print(line, end="")
            process.stdout.close()
            process.wait()
            if process.returncode != 0:
                print(f'{Display.error(process.stderr.read())}')
            process.stderr.close()
        except SystemExit as error: print(Display.invalid_or_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Display.red("Process stopped"))
        except Exception as error:  print(f'{Display.unexpected_error(error)}')


    def _get_argument(self) -> None:
        result        = self._parser_manager._parse("SysCommand", [self._command])
        self._command = result.command
