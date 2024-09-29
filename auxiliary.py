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
