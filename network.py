import socket, argparse, ipaddress, subprocess, platform
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, ARP, Ether
from scapy.all import sr, srp
from scapy.all import conf
from auxiliary import Aux 


class Network: # =============================================================================================
    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        try:    ip = socket.gethostbyname(hostname)
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
        return  ip
    



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
            host, port, verb = self._get_argument_and_flags(data)
            port_dictionary  = self._prepare_ports(port)
            target_ip        = Network._get_ip_by_name(host)
            packages         = self._create_packages(target_ip, port_dictionary, verb)
            responses, _     = self._send_packages(packages)
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
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        arguments = parser.parse_args(data)
        return (arguments.host, arguments.port, arguments.verbose)


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
    def _create_packages(ip:str, ports:dict, verbose:bool) -> list:
        conf.verb = 0 if not verbose else 1
        return [IP(dst=ip)/TCP(dport=port, flags="S") for port in ports.keys()]
    
    
    @staticmethod
    def _send_packages(packages:list) -> tuple[list, list]:
        responses, unanswered = sr(packages, timeout=5, inter=0.1)
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
            case "S":  status = Aux.yellow('Potentially Open')
            case "RA": status = Aux.red('Closed')
            case "F":  status = Aux.red('Connection Closed')
            case "R":  status = Aux.red('Reset')
            case None: status = Aux.red('Filtered')
            case _:    status = Aux.red('Unknown Status')
        print(f'Status: {status:>17} -> {port:>5} - {description}')




class Network_Scanner: # =====================================================================================
    def _execute(self, data:list) -> None:
        try:   
            ip, ping    = self._get_argument_and_flag(data)
            network     = self._get_network(ip)
            self._run_arp_methods(network) if not ping else self._run_ping_methods(network)
        except SystemExit: print(Aux.yellow("Invalid command"))
        except ValueError: print(Aux.yellow("Invalid IP"))
        except KeyboardInterrupt:  print(Aux.orange("Process stopped"))
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flag(data:list) -> tuple[str, bool]:
        parser = argparse.ArgumentParser(prog='netscan', description='Scans the network to discover active hosts')
        parser.add_argument('ip', type=str, help='IP')
        parser.add_argument('-p', '--ping', action='store_true', help='Use ping instead of an ARP package')
        arguments = parser.parse_args(data)
        return (arguments.ip, arguments.ping)


    @staticmethod
    def _get_network(ip:str) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f'{ip}/24', strict=False)


    # NET SCANNER USING ARP ----------------------------------------
    def _run_arp_methods(self, network:ipaddress.IPv4Network) -> None:
        package  = self._create_arp_package(network)
        answered = self._perform_arp_sweep(package)
        self._display_arp_result(answered)


    @staticmethod
    def _create_arp_package(network:ipaddress.IPv4Network) -> Ether:
        arp_request = ARP(pdst=str(network))
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        return broadcast / arp_request


    @staticmethod
    def _perform_arp_sweep(package:Ether) -> list:
        answered, _ = srp(package, timeout=2, verbose=False)
        return answered


    @staticmethod
    def _display_arp_result(answered:list[tuple]) -> None:
        for _, received in answered:
            print(f'{Aux.green("Active host")}: IP {received.psrc:<15}, MAC {received.hwsrc}')


    # NET SCANNER USING PING -----------------------------------------
    def _run_ping_methods(self, network:ipaddress.IPv4Network) ->None:
        futures      = self._ping_sweep(network)
        active_hosts = self._process_result(futures)
        self._display_ping_result(active_hosts)
        

    def _ping_sweep(self, network:ipaddress.IPv4Network) -> dict:
        with ThreadPoolExecutor(max_workers=100) as executor:
            return {executor.submit(self._send_ping, str(ip)): ip for ip in network.hosts()}
            

    def _send_ping(self, ip:str) -> bool:
        command = self._prepare_ping_command(ip)
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    

    @staticmethod
    def _prepare_ping_command(ip:str) -> list:
        flag = '-n' if platform.system() == 'Windows' else '-c'        
        return ['ping', flag, '1', str(ip)]


    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
        active_hosts = []
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_hosts.append(str(ip))
            except Exception as e:
                print(f"{Aux.orange('Error pinging')} {ip}: {e}")
        return active_hosts


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        for ip in active_hosts:
            print(f'{Aux.green("Active host")}: {ip}')
