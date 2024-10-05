class Command_List:
    def _execute(self, arguments:str) -> None:
        commands = (
            f'{Aux.green("ip")}........: Get IP by name',
            f'{Aux.green("geoip")}.....: Get geolocation of an IP',
            f'{Aux.green("pscan")}.....: Port scanner',
            f'{Aux.green("netscan")}...: Network scanner'
        )
        for i in commands: print(i)


class Aux:
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
    def display_invalid_missing():
        return Aux.yellow('Invalid or missing argument/flag. Please, check --help')
