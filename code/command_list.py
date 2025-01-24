# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from display import Display


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
            f'{Display.green("sys")}......: Executes a system command',
            f'{Display.green("pscan")}....: Port scanner',
            f'{Display.green("banner")}...: Banner Grabbing',
            f'{Display.green("osfing")}...: OS Fingerprint',
        ): print(command)
