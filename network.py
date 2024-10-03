import socket, platform, subprocess, argparse, ipaddress
from scapy.all import IP, TCP, sr, conf
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
        except SystemExit:         print(Aux.display_error("Invalid/missing argument"))
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
        try:
            host, port      = self._get_argument_and_flags(data)
            port_dictionary = self._prepare_ports(port)
            ip              = Network._get_ip_by_name(host)
            packages        = self._create_packages(ip, port_dictionary)
            responses, _    = self._send_packages(packages)
            self._process_responses(responses, port_dictionary)
        except SystemExit:         print(Aux.display_invalid_missing())
        except socket.gaierror:    print(Aux.display_error('An error occurred in resolving the host'))
        except socket.error:       print(Aux.display_error(f'It was not possible to connect to "{host}"'))
        except Exception as error: print(Aux.display_unexpected_error(error))
    

    @staticmethod
    def _get_argument_and_flags(data:list) -> tuple[str, int|None]:
        parser = argparse.ArgumentParser(prog='pscan', description='Scans ports on a host')
        parser.add_argument('host', type=str, help='Host name')
        parser.add_argument('-p', '--port', type=int, help='Especify a port to scan')
        arguments = parser.parse_args(data)
        return (arguments.host, arguments.port)


    def _prepare_ports(self, port:int) -> dict:
        return self._get_ports() if port == None else {port: None}


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


    @staticmethod
    def _create_packages(ip:str, ports:dict) -> list:
        conf.verb = 0
        return [IP(dst=ip)/TCP(dport=port, flags="S") for port in ports.keys()]
    
    
    @staticmethod
    def _send_packages(packages:list) -> tuple[list, list]:
        responses, unanswered = sr(packages, timeout=3, inter=0.2)
        return (responses, unanswered)


    def _process_responses(self, responses:list, ports:dict) -> None:
        for sent, received in responses:
            port           = sent[TCP].dport
            response_flags = received[TCP].flags if received else None
            description    = ports[port]
            self._display_result(response_flags, port, description)


    @staticmethod
    def _display_result(response:str|None, port:int, description:str) -> None:
        match response:
            case "SA": status = Aux.green('Opened')
            case "RA": status = Aux.red('Closed')
            case "S":  status = Aux.yellow('Potentially Open')
            case "F":  status = Aux.red('Connection Closed')
            case "R":  status = Aux.red('Reset')
            case None: status = Aux.red('Filtered')
            case _:    status = Aux.red('Unknown Status')
        print(f'Status: {status:>17} -> {port:>5} - {description}')



class Network_Scanner: # =====================================================================================
    def _execute(self, data:list) -> None:
        try:   
            ip, display = self._get_argument_and_flag(data)
            network     = self._get_network(ip)
            self._network_scanner(network)
        except SystemExit:         print(Aux.display_invalid_missing())
        except ValueError:         print(Aux.yellow('Invalid IP'))
        except Exception as error: print(Aux.display_unexpected_error(error))
        else: ...


    @staticmethod
    def _get_argument_and_flag(data:list) -> tuple[str, bool]:
        parser = argparse.ArgumentParser(prog='netscan', description='Scans the network to discover active hosts')
        parser.add_argument('ip', type=str, help='IP')
        parser.add_argument('-d', '--display', action='store_true', help='Displays all messages (closed/opened)')
        arguments = parser.parse_args(data)
        return (arguments.ip, arguments.display)


    @staticmethod
    def _get_network(ip:str) -> ipaddress.IPv4Address:
        ipaddress.ip_address(ip)
        network = ipaddress.ip_network(ip)
        return network


    @staticmethod
    def _network_scanner(network:list) -> None:
        for ip in network.hosts():
            if Network._ping(ip): print(f"Host ativo: {ip}")
        
