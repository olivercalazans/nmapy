# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ssl
from auxiliary import Color


class Banner_Grabbing:
    
    def __init__(self, database, data:list) -> None:
        self._parser_manager = database.parser_manager
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
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except Exception as error:  print(f'{Color.display_unexpected_error(error)}')


    def _get_argument_and_flags(self) -> None:
        """Parses and retrieves the hostname, port, and verbosity flag from the arguments."""
        arguments      = self._parser_manager._parse("BannerGrabbing", self._data)
        self._host     = arguments.host
        self._protocol = arguments.protocol
        self._port     = arguments.port
    

    def _grab_banners_on_the_protocol(self) -> None:
        try:
            protocol = self._protocol_dictionary().get(self._protocol)
            port     = self._port if self._port else protocol['port']
            with protocol['class']() as instance:
                instance._execute_banner_grabbing(self._host, port)
        except Exception as error: print(f'{Color.red("Error while trying to execute the banner grabbing")}.\nERROR: {error}')


    @staticmethod
    def _protocol_dictionary() -> dict:
        return {
            'http':  {'class': HTTP_Banner_grabbing,  'port': 80},
            'https': {'class': HTTPS_Banner_Grabbing, 'port': 443},
            'ssh':   {'class': SSH_Banner_Grabbing,   'port': 22}
        }
        





class HTTP_Banner_grabbing:

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    @staticmethod
    def _execute_banner_grabbing(host:str, port:int) -> None:
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())

                response = sock.recv(4096).decode(errors="ignore")
                print("[+] Resposta do servidor HTTP:")
                print(response)
                
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        print(f"[+] Banner HTTP encontrado: {line}")
        except Exception as error:
            print(f"[-] Error: {error}")





class HTTPS_Banner_Grabbing:

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    @staticmethod
    def _execute_banner_grabbing(host:str, port:int):
        try:
            # Criar um socket seguro (SSL/TLS)
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Enviar uma requisição HTTPS simples
                    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())

                    # Receber e imprimir a resposta
                    response = ssock.recv(4096).decode(errors="ignore")
                    print(f"[+] Resposta do servidor HTTPS:\n{response}")

                    # Opcional: Exibir informações do certificado SSL
                    cert = ssock.getpeercert()
                    print("\n[+] Certificado SSL do servidor:")
                    for key, value in cert.items():
                        print(f"  {key}: {value}")
        except Exception as e:
            print(f"[-] Erro: {e}")





class SSH_Banner_Grabbing:

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    @staticmethod
    def _execute_banner_grabbing(host:str, port:int) -> None:
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(1024).decode(errors="ignore")
                print(f"[+] Banner do servidor SSH:\n{banner}")
        except Exception as e:
            print(f"[-] Erro: {e}")
