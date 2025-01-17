# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys, subprocess
from auxiliary       import Color, Argument_Parser_Manager
from port_scanner    import Port_Scanner
from banner_grabbing import Banner_Grabbing
from os_fingerprint  import OS_Fingerprint


class Main: # ================================================================================================

    def __init__(self) -> None:
        self._stop_flag      = False
        self._parser_manager = Argument_Parser_Manager()


    def _handle_user(self) -> None:
        try:   self._loop()
        except KeyboardInterrupt:  sys.exit()
        except Exception as error: print(Color.display_unexpected_error(error))


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
            print(f'{Color.yellow("Unknown command")} "{command}"')


    def _run_command(self, command:str, arguments:str) -> None:
        try:
            strategy_class = self._get_strategy_dictionary().get(command)
            with strategy_class(self._parser_manager, arguments) as strategy:
                strategy._execute()
        except Exception as error: print(f'{Color.red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _get_strategy_dictionary() -> dict:
        return {
            "help":   Command_List,
            "sys":    System_Command,
            "pscan":  Port_Scanner,
            "banner": Banner_Grabbing,
            "osfing": OS_Fingerprint,
        }





class Command_List: # ========================================================================================

    def __init__(self, _, __):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    @staticmethod
    def _execute() -> None:
        for command in (
            f'{Color.green("sys")}......: Executes a system command',
            f'{Color.green("pscan")}....: Port scanner',
            f'{Color.green("banner")}...: Banner Grabbing',
            f'{Color.green("osfing")}...: OS Fingerprint',
        ): print(command)





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
                print(f'{Color.display_error(process.stderr.read())}')
            process.stderr.close()
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except Exception as error:  print(f'{Color.display_unexpected_error(error)}')


    def _get_argument(self) -> None:
        result        = self._parser_manager._parse("SysCommand", [self._command])
        self._command = result.command





if __name__ == '__main__':
    user = Main()
    user._handle_user()
