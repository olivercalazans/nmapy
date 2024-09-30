class Command_List:
    def _execute(self, arguments:str) -> None:
        commands = (
            f'{Aux._green("pscan")}.....: Port scanner',
            f'{Aux._green("ip")}........: Get IP by name',
            f'{Aux._green("netscan")}...: Network scanner'
        )
        for i in commands: print(i)


class Aux:
    @staticmethod
    def _red(message):
        return '\033[31m' + message + '\033[0m'
    
    @staticmethod
    def _green(message):
        return '\033[32m' + message + '\033[0m'
    
    @staticmethod
    def _yellow(message):
        return '\033[33m' + message + '\033[0m'
    
    @staticmethod
    def _orange(message):
        return '\033[38;5;214m' + message + '\033[0m'
