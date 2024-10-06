import argparse


class Aux: # =================================================================================================
    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'
    
    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'
    
    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'
    
    @staticmethod
    def orange(message:str) -> str:
        return '\033[38;5;214m' + message + '\033[0m'
    
    @staticmethod
    def display_unexpected_error(error:str) -> str:
        return Aux.red('Unexpected error') + f'\nERROR: {error}'
    
    @staticmethod
    def display_error(message:str) -> str:
        return Aux.yellow('ERROR: ') + message
    
    @staticmethod
    def display_invalid_missing() -> str:
        return Aux.yellow(f'Invalid or missing argument/flag. Please, check --help')




class Argument_Parser_Manager: # =============================================================================
    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser(description="Argument Manager")
        self._subparser = self._parser.add_subparsers(dest="class")
        self._argument_class = Argument_Definitions()
        self._add_all_commands()


    def _add_arguments(self, class_name:str, argument_list:list[dict]) -> None:
        class_parser = self._subparser.add_parser(class_name)
        for arg in argument_list:
            if arg['arg_type'] == 'bool':
                class_parser.add_argument(arg["name"], action="store_true", help=arg["help"])
            elif arg['arg_type'] == 'value':
                class_parser.add_argument(arg["name"], type=arg['type'], help=arg["help"])
            else:
                class_parser.add_argument(arg["name"], type=str, help=arg["help"])


    def _add_all_commands(self) -> None:
        for method_name in dir(self._argument_class):
            method = getattr(self._argument_class, method_name)
            if callable(method) and method_name.endswith('_arguments'):
                arguments = method()
                self._add_arguments(arguments[0], arguments[1])


    def _parse(self, data: list) -> argparse.Namespace:
        return self._parser.parse_args(data)
    



class Argument_Definitions: # ================================================================================
    @staticmethod
    def _get_ip_arguments():
        return "Get_Ip", [
            {"arg_type": "arg", "name": 'host', "help": "Host name"}
        ]


    @staticmethod
    def _portscanner_arguments():
        return "PortScanner", [
            {"arg_type": "arg",   "name": 'host',              "help": "Host name"},
            {"arg_type": "value", "name": "-p",   "type": int, "help": "Specify a port to scan"},
            {"arg_type": "bool",  "name": "-v",                "help": "Enable verbose output"}
        ]
    

    @staticmethod
    def _netscanner_arguments():
        return "Netscanner", [
            {"arg_type": "arg",  "name": 'ip', "help": "IP"},
            {"arg_type": "bool", "name": "-p", "help": "Use ping instead of an ARP package"}
        ]
    

    @staticmethod
    def _ip_geolocation_arguments():
        return "GeoIP", [
            {"arg_type": "arg", "name": 'ip', "help": "IP or Hostname"}
        ]
    

    @staticmethod
    def _mac_to_device_arguments():
        return "MacToDev", [
            {"arg_type": "arg", "name": 'mac', "help": "MAC to be looked up"}
        ]
