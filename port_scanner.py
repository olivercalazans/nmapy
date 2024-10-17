# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ipaddress, random, time
from scapy.all import IP, TCP
from scapy.all import sr
from scapy.all import conf, sniff
from auxiliary import Aux, Argument_Parser_Manager, Network



class Port_Scanner:
    """Performs a port scan on a specified host."""

    @staticmethod
    def _execute(database, data:list) -> None:
        """ Executes the port scanning process with error handling."""
        try:
            host, port, verb, decoy = Port_Scanner._get_argument_and_flags(database.parser_manager, data)
            port_dictionary  = Port_Scanner._prepare_ports(port)
            target_ip        = Network._get_ip_by_name(host)
            packets          = Port_Scanner._create_packets(target_ip, port_dictionary, verb)
            responses, _     = Port_Scanner._send_packets(packets)
            Port_Scanner._process_responses(responses, port_dictionary)
        except SystemExit:          print(Aux.display_invalid_missing())
        except socket.gaierror:     print(Aux.display_error('An error occurred in resolving the host'))
        except socket.error:        print(Aux.display_error(f'It was not possible to connect to "{host}"'))
        except Exception as error:  print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> tuple:
        """Parses and retrieves the hostname, port, and verbosity flag from the arguments."""
        arguments = parser_manager._parse("PortScanner", data)
        return (arguments.host, arguments.port, arguments.verbose, arguments.decoy)


    @staticmethod
    def _prepare_ports(port:int) -> dict:
        """Prepares the port or ports to be scanned."""
        return Port_Scanner._get_ports() if port == None else {port: None}


    @staticmethod
    def _get_ports() -> dict:
        """Returns a dictionary of common ports and their services."""
        return { 
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


    @staticmethod
    def _create_packets(ip:str, ports:dict, verbose:bool) -> list:
        """Creates the TCP SYN packets to be sent for scanning the specified ports."""
        conf.verb = 0 if not verbose else 1
        return [IP(dst=ip)/TCP(dport=port, flags="S") for port in ports.keys()]


    @staticmethod
    def _send_packets(packets:list) -> tuple[list, list]:
        """Sends the SYN packets and receives the responses."""
        responses, unanswered = sr(packets, timeout=5, inter=0.1)
        return (responses, unanswered)


    @staticmethod
    def _process_responses(responses:list, ports:dict) -> None:
        """Processes the scan responses and displays the results."""
        for sent, received in responses:
            port           = sent[TCP].dport
            response_flags = received[TCP].flags if received else None
            description    = ports[port] if port in Port_Scanner._get_ports() else 'Generic Port'
            Port_Scanner._display_result(response_flags, port, description)


    @staticmethod
    def _display_result(response:str|None, port:int, description:str) -> None:
        """Displays the scan result for each port."""
        match response:
            case "SA": status = Aux.green('Opened')
            case "S":  status = Aux.yellow('Potentially Open')
            case "RA": status = Aux.red('Closed')
            case "F":  status = Aux.red('Connection Closed')
            case "R":  status = Aux.red('Reset')
            case None: status = Aux.red('Filtered')
            case _:    status = Aux.red('Unknown Status')
        print(f'Status: {status:>17} -> {port:>5} - {description}')


    # DECOY METHODS ---------------------------------------------------------------------------
    @staticmethod
    def _perform_decoy_method():
        ...

    
    @staticmethod
    def _prepare_packets(my_ip:str, subnet_mask:str):
        decoy_packets = Port_Scanner._generate_random_ip_in_subnet(my_ip, subnet_mask)
        all_packets   = Port_Scanner._add_real_packet(decoy_packets, my_ip)


    @staticmethod
    def _generate_random_ip_in_subnet(network_ip:str, subnet_mask:str, count = random.randint(4, 6)) -> list:
        """Takes a network IP and subnet mask, returning a random IP within the valid range."""
        network    = ipaddress.IPv4Network(f"{network_ip}/{subnet_mask}", strict=False)
        hosts      = list(network.hosts())
        random_ips = random.sample(hosts, count)
        return [str(ip) for ip in random_ips]
    

    @staticmethod
    def _add_real_packet(decoy_packets:list, my_ip:str) -> list:
        packet_number = len(decoy_packets)
        index         = random.randint(packet_number // 2, packet_number - 1)
        return decoy_packets.append(index, my_ip)


    @staticmethod
    def _capture_real_response(my_ip:str, port:int, timeout=5):
        def packet_filter(packet):
            return (packet.haslayer(IP) and 
                    packet.haslayer(TCP) and 
                    packet[IP].dst == my_ip and 
                    packet[TCP].dport == port)
        response = sniff(filter=f"tcp and dst host {my_ip} and tcp port {port}",
                         prn=lambda x: x.summary(), 
                         lfilter=packet_filter, timeout=timeout, count=1)
        return response if response else None
    

    @staticmethod
    def _send_decoy_and_real_packets():
        ...
