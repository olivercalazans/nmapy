import socket

class Network_MixIn:
    @staticmethod
    def _ip(host_name:str) -> str:
        return Network_MixIn._get_ip_by_name(host_name)


    @staticmethod
    def _get_ip_by_name(host_name:str) -> str:
        try:    ip = socket.gethostbyname(host_name)
        except: ip = 'ERROR. Invalid hostname'
        return  ip


    # PORTSCAN --------------------------------------------------------------------------------------------------
    @staticmethod
    def _portscan(host:str) -> str:
        ip = Network_MixIn._get_ip_by_name(host)
        try:   result = Network_MixIn._convert_to_string(Network_MixIn._scan( ip, Network_MixIn._ports()))
        except socket.gaierror: result = '<single>:ERROR: problems with DNS'
        except socket.error: result = '<single>:ERROR: It was not possible to connect to the server'
        else:  result = f'<mult>:{result}'
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
