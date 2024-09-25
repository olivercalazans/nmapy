import argparse

class Argumet_Parse_Service:
    def __init__(self) -> None:
        self._parser      = argparse.ArgumentParser(description='')
        self._sub_parsers = self._parser.add_subparsers(dest='')
        self._setup_service()