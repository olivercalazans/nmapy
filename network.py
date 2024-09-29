import socket, platform, subprocess
from auxiliary import *

class Network:
    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        try:    ip = socket.gethostbyname(hostname)
        except: ip = f'{Aux._yellow("ERROR")}: Invalid hostname ({hostname})'
        return  ip


    # IP BY NAME ---------------------------------------------------------------------------------------------
    @staticmethod
    def _ip(host_name:str) -> None:
        print(Network._get_ip_by_name(host_name))


    # PORTSCAN -----------------------------------------------------------------------------------------------
    @staticmethod
    def _portscan(host:str, ports:dict) -> None:
        ip = Network._get_ip_by_name(host)
        try:   Network._scan(ip, ports)
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


    # PING SWEEP ---------------------------------------------------------------------------------------------
    @staticmethod
    def _network_scann(network_prefix:str) -> None:
        for host_bits in range(1, 255):
            ip = f"{network_prefix}{host_bits}"
            if Network._ping(ip): print(f"Host ativo: {ip}")


    @staticmethod
    def _ping(ip:str) -> bool:
        flag    = '-n' if platform.system() == 'Windows' else '-c'
        command = ['ping', flag, '1', ip]
        result  = subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result
        
