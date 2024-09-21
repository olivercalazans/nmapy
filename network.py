import socket

class Network:
    @staticmethod
    def _get_ip_by_name(host_name:str) -> str:
        try:    ip = socket.gethostbyname(host_name)
        except: ip = 'ERROR. Invalid hostname'
        return  ip


    @staticmethod
    def _ip(host_name:str) -> str:
        return Network._get_ip_by_name(host_name)


    # PORTSCAN -------------------------------------------------------------------------------------------------
    @staticmethod
    def _portscan(host:str) -> list[str]:
        ip = Network._get_ip_by_name(host)
        try:   result = Network._scan( ip, Network._ports())
        except socket.gaierror: result = 'ERROR: An error occurred in resolving the host'
        except socket.error: result = f'ERROR: It was not possible to connect to {host}'
        return result
    

    @staticmethod
    def _ports() -> dict:
        ports = { 
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
        return ports

    
    @staticmethod
    def _scan(ip:str, ports:dict) -> list:
        data = list()
        for port in ports.keys():
            portscan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            portscan_socket.settimeout(3)
            result = portscan_socket.connect_ex((ip, port))
            status = 'Closed'
            if result == 0: status = 'Opened'
            data.append(f' Port {port:>4} : {ports[port]} (STATUS -> {status})')
            portscan_socket.close()
        return data
