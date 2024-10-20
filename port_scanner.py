# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ipaddress, random, time, threading
from scapy.all import IP, TCP
from scapy.all import sr, sr1, send
from scapy.all import conf, packet
from auxiliary import Aux, Argument_Parser_Manager, Network



class Port_Scanner:
    """Performs a port scan on a specified host."""

    @staticmethod
    def _execute(database, data:list) -> None:
        """ Executes the port scanning process with error handling."""
        try:
            host, port, verb, decoy = Port_Scanner._get_argument_and_flags(database.parser_manager, data)
            ports      = Port_Scanner._prepare_ports(port)
            target_ip  = Network._get_ip_by_name(host)
            interface  = Network._select_interface()
            conf.iface = interface
            conf.verb  = 0 if not verb else 1
            responses  = Port_Scanner._get_the_result_according_to_the_transmission_method(decoy, target_ip, ports, interface)
            Port_Scanner._process_responses(responses, ports)
        except SystemExit:         print(Aux.display_invalid_missing())
        except KeyboardInterrupt:  print(Aux.orange("Process stopped"))
        except socket.gaierror:    print(Aux.display_error('An error occurred in resolving the host'))
        except socket.error:       print(Aux.display_error(f'It was not possible to connect to "{host}"'))
        except Exception as error: print(Aux.display_unexpected_error(error))


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
    def _get_the_result_according_to_the_transmission_method(decoy:int, target_ip:str, ports:dict, interface:str) -> list:
        """Retrieves the scan results based on the specified transmission method."""
        if isinstance(decoy, int):
            response = Port_Scanner._perform_decoy_method(decoy, interface, target_ip)
        else:
            response = Port_Scanner._perform_normal_scan(target_ip, ports)
        return response
    

    # NORMAL SCAN --------------------------------------------------------------------------------------------
    @staticmethod
    def _perform_normal_scan(target_ip:str, port_dictionary:dict) -> list:
        """Performs a normal scan on the specified target IP address."""
        packets      = Port_Scanner._create_packets(target_ip, port_dictionary)
        responses, _ = Port_Scanner._send_packets(packets)
        return responses


    @staticmethod
    def _create_packets(ip:str, ports:dict) -> list:
        """Creates the TCP SYN packets to be sent for scanning the specified ports."""
        return [IP(dst=ip)/TCP(dport=port, flags="S") for port in ports.keys()]


    @staticmethod
    def _send_packets(packets:list) -> tuple[list, list]:
        """Sends the SYN packets and receives the responses."""
        responses, unanswered = sr(packets, timeout=5, inter=0.1)
        return (responses, unanswered)


    # DECOY METHODS ------------------------------------------------------------------------------------------
    received_packet = None
    
    @staticmethod
    def _perform_decoy_method(port:int, interface:str, target_ip:str) -> list:
        """Performs a decoy scan method using the specified port and network interface."""
        my_ip    = Network._get_ip_address(interface)
        netmask  = Network._get_subnet_mask(interface)
        ips      = Port_Scanner._prepare_decoy_and_real_ips(my_ip, netmask)
        Port_Scanner._send_decoy_and_real_packets(ips, my_ip, target_ip, port)
        return Port_Scanner.received_packet
        
    
    @staticmethod
    def _prepare_decoy_and_real_ips(my_ip:str, subnet_mask:str) -> None:
        """ Prepares a list of decoy IPs and adds the real IP to the list."""
        decoy_packets = Port_Scanner._generate_random_ip_in_subnet(my_ip, subnet_mask)
        return Port_Scanner._add_real_packet(decoy_packets, my_ip)


    @staticmethod
    def _generate_random_ip_in_subnet(network_ip:str, subnet_mask:str, count = random.randint(4, 6)) -> list:
        """Takes a network IP and subnet mask, returning a random IP within the valid range."""
        network    = ipaddress.IPv4Network(f"{network_ip}/{subnet_mask}", strict=False)
        hosts      = list(network.hosts())
        random_ips = random.sample(hosts, count)
        return [str(ip) for ip in random_ips]
    

    @staticmethod
    def _add_real_packet(decoy_ips:list, my_ip:str) -> list:
        """Inserts the real IP address into a list of decoy IPs at a random position."""
        packet_number = len(decoy_ips)
        index         = random.randint(packet_number // 2, packet_number - 1)
        decoy_ips.insert(index, my_ip)
        return decoy_ips
        

    @staticmethod
    def _send_decoy_and_real_packets(ip_list:list, my_ip:str ,target_ip:str, port:int) -> None:
        """Sends both decoy and real packets to the specified target IP address."""
        for ip in ip_list:
            if ip == my_ip:
                thread = threading.Thread(target=Port_Scanner._send_real_packet, args=(my_ip, target_ip, port))
                thread.start()
            else:
                Port_Scanner._send_decoy_packet(ip, target_ip, port)
            delay = random.uniform(1, 3)
            print(f'{Aux.green("Packet sent")}: {ip}, Delay: {delay}')
            time.sleep(delay)


    @staticmethod
    def _create_packet(source_ip:str, target_ip:str, port:int) -> packet:
        """Creates a TCP SYN packet for a specified source and target IP address."""
        return IP(src=source_ip, dst=target_ip) / TCP(dport=port, flags="S")


    @staticmethod
    def _send_real_packet(my_ip:str, target_ip:str, port:int) -> None:
        """Sends a real TCP SYN packet to the specified target IP address."""
        real_packet = Port_Scanner._create_packet(my_ip, target_ip, port)
        response    = sr1(real_packet, verbose=0)
        Port_Scanner.received_packet = [(real_packet, response)]


    @staticmethod
    def _send_decoy_packet(decoy_ip:str, target_ip:str, port:int) -> None:
        """Sends a decoy TCP SYN packet to the specified target IP address."""
        decoy_packet = Port_Scanner._create_packet(decoy_ip, target_ip, port)
        send(decoy_packet, verbose=0)


    # PROCESS DATA -------------------------------------------------------------------------------------------
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

