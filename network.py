import socket

class Network:
    @staticmethod
    def _get_ip_by_name(host_name:str) -> str:
        try:    ip = socket.gethostbyname(host_name)
        except: ip = 'ERROR. Invalid hostname'
        return  ip


    # IP BY NAME ---------------------------------------------------------------------------------------------
    @staticmethod
    def _ip(host_name:str) -> str:
        print(Network._get_ip_by_name(host_name))


    # PORTSCAN -----------------------------------------------------------------------------------------------
    @staticmethod
    def _portscan(host:str, ports:list) -> None:
        ip = Network._get_ip_by_name(host)
        try:   Network._scan(ip, ports)
        except socket.gaierror: print('ERROR: An error occurred in resolving the host')
        except socket.error:    print(f'ERROR: It was not possible to connect to {host}')
        except Exception as error: print(f'ERROR: {error}') 

    
    @staticmethod
    def _scan(ip:str, ports:dict) -> list:
        data = list()
        for port in ports.keys():
            portscan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            portscan_socket.settimeout(3)
            result = portscan_socket.connect_ex((ip, port))
            status = 'Closed'
            if result == 0: status = 'Opened'
            message = f' Port {port:>4} : {ports[port]} (STATUS -> {status})'
            print(message)
            data.append(message)
            portscan_socket.close()
        return data
