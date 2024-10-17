# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
This file contains classes used to manage and interact with the user interface.
It handles input processing and command execution.
"""


from auxiliary import Aux, Argument_Parser_Manager, Files
from simple_commands import *
from network_scanner import *
from port_scanner import *



class Main: # ================================================================================================
    """
    Handles user interaction by receiving input and verifying if the given command exists.
    
    Methods:
        _handle_user().................................: Manages the user input loop and handles errors.
        _loop()........................................: Starts a loop to receive input data from the user.
        _separates_command_from_arguments(input_data)..: Separates the command from its arguments.
        _check_if_the_method_exists(command, arguments): Checks if the command exists and calls its corresponding function.
        _run_command(command, arguments)...............: Executes the given command with its arguments.
        _get_strategy_dictionary().....................: Returns a dictionary that maps commands to their respective classes.
    """

    def __init__(self) -> None:
        """Initializes the Main class, setting up the stop flag and auxiliary data."""
        self._stop_flag = False
        self._database  = DataBase()


    @property
    def _stop(self) -> None:
        """Stops the loop that receives user input by setting the stop flag to True."""
        self._stop_flag = True


    def _handle_user(self) -> None:
        """This method is used to do error handling of the loop"""
        try:   self._loop()
        except Exception as error: print(Aux.display_unexpected_error(error))


    def _loop(self) -> None:
        """Loop that receives input data from user."""
        while not self._stop_flag:
            print('\nWrite "help" to see the commands ' + '=' * 40)
            input_data         = input('>> ').split(' ')
            command, arguments = self._separates_command_from_arguments(input_data)
            self._check_if_the_method_exists(command, arguments)


    @staticmethod
    def _separates_command_from_arguments(input_data) -> tuple[str, list|None]:
        """Separates the input data into command and arguments."""
        command   = input_data[0]
        arguments = input_data[1:] or [None]
        return (command, arguments)


    def _check_if_the_method_exists(self, command:str, arguments:tuple) -> None:
        """Checks if the provided command exists in the strategy dictionary and executes it."""
        if command in self._get_strategy_dictionary():
            self._run_command(command, arguments)
        elif command == 'exit':
            self._stop
        else:
            print(f'{Aux.yellow("Unknown command")} "{command}"')


    def _run_command(self, command:str, arguments:str) -> None:
        """Executes the command by calling the corresponding class method."""
        strategy = self._get_strategy_dictionary().get(command)
        try:   strategy._execute(self._database, arguments)
        except Exception as error: print(f'{Aux.red("Error while trying to execute the command")}.\nERROR: {error}')


    @staticmethod
    def _get_strategy_dictionary() -> dict:
        """Returns the class dictionary."""
        return {
            "help":    Command_List(),
            "iface":   Interfaces(),
            "ip":      Get_IP(),
            "geoip":   IP_Geolocation(),
            "macdev":  MAC_To_Device(),
            "netscan": Network_Scanner(),
            "pscan":   Port_Scanner(),
        }





class DataBase: # ======================================================================================
    """
    Stores auxiliary data and instances needed for other classes.
    This includes managing argument parsers and storing databases like the MAC dictionary.
    
    Attributes:
        _parser_manager (Argument_Parser_Manager): Manages the argument parsers.
        _mac_dictionary (list)...................: Stores the MAC address database.
    
    Methods:
        parser_manager: Returns the argument parser manager.
        mac_dictionary: Returns the MAC address database.
    """

    def __init__(self) -> None:
        self._parser_manager   = Argument_Parser_Manager()
        self._mac_dictionary   = Files()._get_mac_list()


    @property
    def parser_manager(self) -> Argument_Parser_Manager:
        """Returns the Argument_Parser_Manager instance for handling argument parsing."""
        return self._parser_manager


    @property
    def mac_dictionary(self) -> list[dict]:
        """Returns the MAC address dictionary used to find the device manufacturer."""
        return self._mac_dictionary




if __name__ == '__main__':
    user = Main()
    user._handle_user()
