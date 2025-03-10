# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from typing import NewType



# TYPE HITS -------------------------------------------------------------------

RawPacket = NewType("RawPacket", bytes)



# FUNCTIONS -------------------------------------------------------------------

def green(message:str) -> str:
    return '\033[32m' + message + '\033[0m'

def red(message:str) -> str:
    return '\033[31m' + message + '\033[0m'

def yellow(message:str) -> str:
    return '\033[33m' + message + '\033[0m'

def unexpected_error(error:str) -> str:
    return red('Unexpected error') + f'\nERROR: {error}'