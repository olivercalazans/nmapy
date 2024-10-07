# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from auxiliary import Aux, Argument_Parser_Manager, DataBases
from commands import *


class Main: # ================================================================================================
    def __init__(self) -> None:
        self._stop_flag      = False
        self._auxiliary_data = Auxiliary_Data()


    @property
    def _stop(self) -> None:
        self._stop_flag = True


    def _handle_user(self) -> None:
        try:   self._loop()
        except Exception as error: print(Aux.display_unexpected_error(error))


    def _loop(self) -> None:
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data         = input('>> ').split(' ')
            command, arguments = self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists(command, arguments)


    @staticmethod
    def _separates_command_from_arguments(input_data) -> tuple[str, list|None]:
        command   = input_data[0]
        arguments = input_data[1:] or [None]
        return (command, arguments)


    def _check_if_the_method_exists(self, command:str, arguments:tuple) -> None:
        if command in self._get_strategy_dictionary():
            self._run_command(command, arguments)
        elif command == 'exit':
            self._stop
        else:
            print(f'{Aux.yellow("Unknown command")} "{command}"')


    def _run_command(self, command:str, arguments:str) -> None:
        strategy = self._get_strategy_dictionary().get(command)
        try:   strategy._execute(self._auxiliary_data, arguments)
        except Exception as error: print(f'{Aux.red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _get_strategy_dictionary() -> dict:
        return {
            "help":    Command_List(),
            "ip":      Get_IP(),
            "geoip":   IP_Geolocation(),
            "pscan":   Port_Scanner(),
            "netscan": Network_Scanner(),
            "macdev":  MAC_To_Device(),
        }





class Auxiliary_Data: # ======================================================================================
    def __init__(self) -> None:
        self._parser_manager = Argument_Parser_Manager()
        self._databases      = DataBases()
        self._mac_dictionary = self._databases._get_mac_list()


    @property
    def parser_manager(self) -> Argument_Parser_Manager:
        return self._parser_manager


    @property
    def mac_dictionary(self) -> list[dict]:
        return self._mac_dictionary



if __name__ == '__main__':
    user = Main()
    user._handle_user()
