# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


class Display: # ===============================================================================================

    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'

    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'

    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'

    @staticmethod
    def unexpected_error(error:str) -> str:
        return Display.red('Unexpected error') + f'\nERROR: {error}'

    @staticmethod
    def error(message='') -> str:
        return Display.yellow('ERROR: ') + message

    @staticmethod
    def invalid_or_missing() -> str:
        return Display.yellow(f'Invalid or missing argument/flag. Please, check --help')