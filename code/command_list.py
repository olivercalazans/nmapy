# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from display import *


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
            f'{green("sys")}......: Executes a system command',
            f'{green("pscan")}....: Port scanner',
            f'{green("banner")}...: Banner Grabbing',
            f'{green("osfing")}...: OS Fingerprint',
        ): print(command)
