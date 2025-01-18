# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from auxiliary import Color, Argument_Parser_Manager


class OS_Fingerprint:
    def __init__(self, parser_manager:Argument_Parser_Manager, data:list) -> None:
        self._parser_manager = parser_manager
        self._data           = data
        self._target_ip      = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            self._get_argument()
            print(f'{Color.yellow("Function still under development")}')
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except ValueError as error: print(Color.display_error(error))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self) -> str:
        arguments       = self._parser_manager._parse("OSFingerprint", self._data)
        self._target_ip = arguments.host


    