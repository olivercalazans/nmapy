import argparse, socket, platform, subprocess
from auxiliary import *

class Network: # =============================================================================================
    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        try:    ip = socket.gethostbyname(hostname)
        except: ip = f'{Aux._yellow("ERROR")}: Invalid hostname ({hostname})'
        return  ip
    

    @staticmethod
    def _ping(ip:str) -> bool:
        flag    = '-n' if platform.system() == 'Windows' else '-c'
        command = ['ping', flag, '1', ip]
        result  = subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result




class Get_IP: # ==============================================================================================
    def _execute(self, data:list):
        try:   argument = self._get_argument(data)
        except SystemExit: print(f'{Aux._yellow("Invalid/missing argument")}')
        except Exception as error: print(f'{Aux._red("Unexpect error")}\nERROR: {error}')
        else:  self._ip(argument)
    

    @staticmethod
    def _get_argument(argument:list) -> str:
        parser = argparse.ArgumentParser(prog='ip', description='Get the IP of a host')
        parser.add_argument('argument', type=str, help='Hostname')
        hostname = parser.parse_args(argument)
        return hostname.argument


    @staticmethod
    def _ip(host_name:str) -> None:
        print(Network._get_ip_by_name(host_name))




class Port_Scanner: # ========================================================================================
    def _execute(self, data:list) -> None:
        try:   argument, flags = self._get_argument_and_flags(data)
        except ValueError as error: print(error)
        except Exception as error:  print(f'{Aux._red("Unexpected error")}:\nERROR: {error}')
        else:  self._prepare_ports(argument, flags)


    def _get_argument_and_flags(self, data:list) -> tuple[str, dict]:
        parser = self._argparser_information()
        try:   arguments = parser.parse_args(data)
        except SystemExit: raise ValueError(f'{Aux._yellow("Invalid argument/flag or missed value")}. Please, check --help')
        except Exception:  raise ValueError(f'{Aux._red("Unknown error")}, check --help')
        return (arguments.argument, arguments.port)
    

    @staticmethod
    def _argparser_information() -> object:
        parser = argparse.ArgumentParser(prog='pscan', description='Portscan of an IP/Host')
        parser.add_argument('argument', type=str, help='Host name')
        parser.add_argument('-p', '--port', type=int, help='Especify a port to scan')
        return parser


    def _prepare_ports(self, argument:str, port:int) -> None:
        port_dictionary = self._get_ports()
        if port in port_dictionary: port_dictionary = {port: port_dictionary[port]}
        elif port is not None:      port_dictionary = {port: 'Generic port'}
        self._portscan(argument, port_dictionary)


    @staticmethod
    def _get_ports() -> dict:
        PORTS = { 
            21  : 'FTP - File Transfer Protocol',  
            22  : 'SSH - Secure Shell',  
            23  : 'Telnet',  
            25  : 'SMTP - Simple Mail Transfer Protocol',   
            53  : 'DNS - Domain Name System', 
            80  : 'HTTP - HyperText Transfer Protocol', 
            110 : 'POP3 - Post Office Protocol version 3', 
            443 : 'HTTPS - HTTP Protocol over TLS/SSL', 
            5432: 'PostgreSQL database system', 
            8080: 'Jakarta Tomcat'
        }
        return PORTS


    def _portscan(self, host:str, ports:dict) -> None:
        ip = Network._get_ip_by_name(host)
        try:   self._scan(ip, ports)
        except socket.gaierror: print(f'{Aux._yellow("ERROR")}: An error occurred in resolving the host')
        except socket.error:    print(f'{Aux._yellow("ERROR")}: It was not possible to connect to {host}')
        except Exception as error: print(f'{Aux._red("ERROR")}: {error}') 

    
    @staticmethod
    def _scan(ip:str, ports:dict) -> None:
        for port in ports.keys():
            portscan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            portscan_socket.settimeout(3)
            result = portscan_socket.connect_ex((ip, port))
            status = Aux._red('Closed')
            if result == 0: status = Aux._green('Opened')
            message = f' Port {port:>4} : {ports[port]} (STATUS -> {status})'
            print(message)
            portscan_socket.close()




class Network_Scanner: # =====================================================================================
    @staticmethod
    def _network_scann(network_prefix:str) -> None:
        for host_bits in range(1, 255):
            ip = f"{network_prefix}{host_bits}"
            if Network._ping(ip): print(f"Host ativo: {ip}")
        
