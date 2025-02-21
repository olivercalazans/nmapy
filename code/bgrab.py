# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ssl
from arg_parser import Argument_Parser_Manager
from display    import *


class Banner_Grabbing:

    def __init__(self, parser_manager:Argument_Parser_Manager, data:list) -> None:
        self._parser_manager = parser_manager
        self._data           = data
        self._host           = None
        self._protocol       = None
        self._port           = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            self._get_argument_and_flags()
            self._grab_banners_on_the_protocol()
        except SystemExit as error: print(invalid_or_missing()) if not error.code == 0 else print()
        except Exception as error:  print(f'{unexpected_error(error)}')


    def _get_argument_and_flags(self) -> None:
        arguments      = self._parser_manager._parse("BannerGrabbing", self._data)
        self._host     = arguments.host
        self._protocol = arguments.protocol
        self._port     = arguments.p


    def _grab_banners_on_the_protocol(self) -> None:
        try:
            protocol = self._protocol_dictionary().get(self._protocol)
            port     = self._port if self._port else protocol['port']
            protocol['func'](self._host, port)
        except Exception as error:
            print(f'{red("Error while trying to execute the banner grabbing")}.\nERROR: {error}')


    @staticmethod
    def _protocol_dictionary() -> dict:
        return {
            'http':  {'func': _http_banner_grabbing,  'port': 80},
            'https': {'func': _https_banner_grabbing, 'port': 443},
            'ssh':   {'func': _ssh_banner_grabbing,   'port': 22}
        }



# FUNCTIONS ==================================================================================================

def _http_banner_grabbing(host:str, port:int) -> None:
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode(errors="ignore")
            print("[+] HTTP server response:")
            print(response)
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    print(f"[+] HTTP banner found: {line}")
    except Exception as error:
        print(f"[-] Error: {error}")



def _https_banner_grabbing(host:str, port:int):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())

                response = ssock.recv(4096).decode(errors="ignore")
                print(f"[+] HTTPS server response:\n{response}")

                cert = ssock.getpeercert()
                print("\n[+] SSL certificate of the server:")
                for key, value in cert.items():
                    print(f"  {key}: {value}")
    except Exception as error:
        print(f"[-] Error: {error}")



def _ssh_banner_grabbing(host:str, port:int) -> None:
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore")
            print(f"[+] SSH server banner:\n{banner}")
    except Exception as error:
        print(f"[-] Error: {error}")
