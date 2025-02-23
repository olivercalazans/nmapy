# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ssl
from arg_parser import Argument_Manager as ArgParser
from display    import *


class Banner_Grabbing:

    def __init__(self, parser_manager:ArgParser) -> None:
        self._host:str     = None
        self._protocol:str = None
        self._port:int     = None
        self._get_argument_and_flags(parser_manager)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._host     = parser_manager.host
        self._protocol = parser_manager.protocol
        self._port     = parser_manager.port


    def _execute(self) -> None:
        try:   self._grab_banners_on_the_protocol()
        except ConnectionRefusedError as error: print(f'{yellow("Connection refused")}: {error}')
        except Exception as error:              print(f'{unexpected_error(error)}')


    def _grab_banners_on_the_protocol(self) -> None:
        protocol = self._protocol_dictionary().get(self._protocol)
        port     = self._port if self._port else protocol['port']
        protocol['func'](self._host, port)


    @staticmethod
    def _protocol_dictionary() -> dict:
        return {
            'ssh':   {'func': _ssh_banner_grabbing,   'port': 22},
            'http':  {'func': _http_banner_grabbing,  'port': 80},
            'https': {'func': _https_banner_grabbing, 'port': 443},
        }



# FUNCTIONS ==================================================================================================

def _ssh_banner_grabbing(host:str, port:int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        banner = sock.recv(1024).decode(errors="ignore")
        banner = banner.split(',')
        print(green("SSH server banner"))
        for line in banner:
            if not line == '': print(f'  - {line.strip()}')



def _http_banner_grabbing(host:str, port:int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")

        print(green('HTTP server response:'))
        for line in response.split("\r\n"):
            if line == '': continue
            info = line.split(':', 1)
            if len(info) > 1: print(f'  {green(info[0])}:{info[1]}')
            else:             print(f'  {green(info[0])}')



def _https_banner_grabbing(host:str, port:int):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:            
            cert = ssock.getpeercert()
            
            print(f"{host} SSL Certificate:")
            if cert:
                for field, value in cert.items():
                    print(f"{field}: {value}")
            else:
                print(yellow('No SSL certificates returned'))
            
            print("  - HTTP header (if present):")
            ssock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            response = ssock.recv(1024)
            for line in response.decode(errors='ignore').split("\r\n"):
                if line == '': continue
                info = line.split(':', 1)
                if len(info) > 1: print(f'  {green(info[0])}:{info[1]}')
                else:             print(f'  {green(info[0])}')
