import socket, platform, subprocess, argparse
from auxiliary import Aux

class Network: # =============================================================================================
    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        try:    ip = socket.gethostbyname(hostname)
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
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
        except SystemExit: print(Aux.display_error("Invalid/missing argument"))
        except Exception as error: print(Aux.display_unexpected_error(error))
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
        except SystemExit: print(Aux.display_error('Invalid argument/flag or missing value. Please, check --help'))
        except Exception as error: print(Aux.display_unexpected_error(error))
        else:  self._prepare_ports(argument, flags)
    

    @staticmethod
    def _get_argument_and_flags(data:list) -> tuple[str, dict]:
        parser = argparse.ArgumentParser(prog='pscan', description='Portscan of an IP/Host')
        parser.add_argument('argument', type=str, help='Host name')
        parser.add_argument('-p', '--port', type=int, help='Especify a port to scan')
        arguments = parser.parse_args(data)
        return (arguments.argument, arguments.port)


    def _prepare_ports(self, argument:str, port:int) -> None:
        port_dictionary = self._get_ports()
        if port in port_dictionary: port_dictionary = {port: port_dictionary[port]}
        elif port is not None:      port_dictionary = {port: 'Generic port'}
        self._portscan(argument, port_dictionary)


    @staticmethod
    def _get_ports() -> dict:
        PORTS = { 
            21   : 'FTP - File Transfer Protocol',  
            22   : 'SSH - Secure Shell',  
            23   : 'Telnet',  
            25   : 'SMTP - Simple Mail Transfer Protocol',   
            53   : 'DNS - Domain Name System', 
            80   : 'HTTP - HyperText Transfer Protocol', 
            110  : 'POP3 - Post Office Protocol version 3', 
            443  : 'HTTPS - HTTP Protocol over TLS/SSL',
            3306 : 'MySQL/MariaDB',
            3389 : 'RDP - Remote Desktop Protocol',
            5432 : 'PostgreSQL database system',
            5900 : 'VNC - Virtual Network Computing',
            6379 : 'Redis',
            8080 : 'Jakarta Tomcat',
            27017: 'MongoDB'
        }
        return PORTS


    def _portscan(self, host:str, ports:dict) -> None:
        ip = Network._get_ip_by_name(host)
        try:   self._scan(ip, ports)
        except socket.gaierror: print(Aux.display_error('An error occurred in resolving the host'))
        except socket.error:    print(Aux.display_error(f'It was not possible to connect to {host}'))
        except Exception as error: print(Aux.display_unexpected_error(error))

    
    @staticmethod
    def _scan(ip:str, ports:dict) -> None:
        for port, description in ports.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as portscan_socket:
                portscan_socket.settimeout(3)
                status = Aux.green('Opened') if portscan_socket.connect_ex((ip, port)) == 0 else Aux.red('Closed')
                print(f' Port {port:>5} : {description} (STATUS -> {status})')




class Network_Scanner: # =====================================================================================
    def _execute(self, data:list) -> None:
        ...

    
    @staticmethod
    def _get_argument_and_flag(data:list) -> tuple[str, str]:
        parser = argparse.ArgumentParser(prog='netscan', description='Scans the network to discover active hosts')
        parser.add_argument('argument', type=str, help='Network')
        parser.add_argument('-d', '--display', type=int, help='Displays all messages (closed/opened)')
        arguments = parser.parse_args(data)
        return (arguments.argument, arguments.display)


    @staticmethod
    def _network_scanner(network_prefix:str) -> None:
        for host_bits in range(1, 255):
            ip = f"{network_prefix}{host_bits}"
            if Network._ping(ip): print(f"Host ativo: {ip}")
        
