# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ipaddress, random, time, threading, sys
from scapy.all import IP, TCP
from scapy.all import sr, send
from scapy.all import conf, Packet
from network   import Network
from auxiliary import Color, Argument_Parser_Manager


class Port_Scanner:
    """Performs a port scan on a specified host."""

    def __init__(self) -> None:
        self._host             = None
        self._flags            = None
        self._ports_to_be_used = None
        self._target_ip        = None
        self._responses        = list()
        self._lock             = threading.Lock()
        self._my_ip_address    = None
        self._all_ports        = { 
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


    def _execute(self, database, data:list) -> None:
        """ Executes the port scanning process with error handling."""
        try:
            self._get_argument_and_flags(database.parser_manager, data)
            self._target_ip = Network._get_ip_by_name(self._host, True)
            conf.verb       = 0
            self._get_result_by_transmission_method()
            self._process_responses()
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except socket.gaierror:     print(Color.display_error('An error occurred in resolving the host'))
        except socket.error:        print(Color.display_error(f'It was not possible to connect to "{self._host}"'))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:Argument_Parser_Manager, data:list) -> None:
        """Parses and retrieves the hostname, port, and verbosity flag from the arguments."""
        arguments   = parser_manager._parse("PortScanner", data)
        self._host  = arguments.host
        self._flags = {
            'ports':   arguments.port,
            'random':  arguments.random_order,
            'delay':   arguments.delay,
            'decoy':   arguments.decoy,
        }


    def _prepare_ports(self, specified_ports = None) -> None:
        """Prepares the port or ports to be scanned."""
        if specified_ports: self._ports_to_be_used = [int(valor) for valor in specified_ports.split(",")]
        else:               self._ports_to_be_used = list(self._all_ports.keys())
        if self._flags['random']: 
            self._ports_to_be_used = random.sample(self._ports_to_be_used, len(self._ports_to_be_used))


    def _get_result_by_transmission_method(self) -> list:
        """Retrieves the scan results based on the specified transmission method."""
        if isinstance(self._flags['decoy'], str):
            self._perform_decoy_method()
        else:
            self._perform_normal_scan()


    # NORMAL SCAN --------------------------------------------------------------------------------------------
    def _perform_normal_scan(self) -> None:
        """Performs a normal scan on the specified target IP address."""
        self._prepare_ports(self._flags['ports'])
        packets = [self._create_tpc_ip_packet(port) for port in self._ports_to_be_used]
        if self._flags['delay']: 
            self._async_sending(packets)
        else: 
            self._send_packets(packets)


    def _create_tpc_ip_packet(self, port, source_ip=None) -> list:
        """Creates the TCP SYN packet"""
        return IP(src=source_ip, dst=self._target_ip) / TCP(dport=port, flags="S")


    def _send_packets(self, packets:list) -> None:
        """Sends the SYN packets and receives the responses."""
        responses, unanswered = sr(packets, timeout=5, inter=0.1)
        self._responses = responses


    def _async_sending(self, packets:list) -> None:
        """Sends TCP packets in concurrent threads with an optional delay between each send."""
        delay   = self._get_delay_time_list(self._flags['delay'], len(packets))
        threads = []
        for index ,packet in enumerate(packets):
            thread = threading.Thread(target=self._async_send_packet, args=(packet,))
            threads.append(thread)
            thread.start()
            sys.stdout.write(f'\rPacket sent: {index}/{len(packets)} - {delay[index]:.2}s')
            sys.stdout.flush()
            time.sleep(delay[index])
        for thread in threads:
            thread.join()
        print('\n')


    @staticmethod
    def _get_delay_time_list(delay:bool|str, packet_number:int) -> list:
        """Generates a list of delay times for sending packets."""
        match delay:
            case True: return [random.uniform(1, 3) for _ in range(packet_number)]
            case _:    return Port_Scanner._create_delay_time_list(delay, packet_number)


    @staticmethod
    def _create_delay_time_list(delay:str, packet_number:int) -> list:
        """Creates a list of delay times based on a specified range or fixed value"""
        values = [float(value) for value in delay.split('-')]
        if len(values) > 1: return [random.uniform(values[0], values[1]) for _ in range(packet_number)]
        return [values[0] for _ in range(packet_number)]


    def _async_send_packet(self, packet:Packet) -> None:
        """Sends a single TCP SYN packet asynchronously and stores the response."""
        response = Network._send_single_packet(packet)
        with self._lock:
            self._responses.append((packet, response))


    # DECOY METHODS ------------------------------------------------------------------------------------------    
    def _perform_decoy_method(self) -> None:
        """Performs a decoy scan method using the specified port and network interface."""
        self._prepare_ports(self._flags['decoy'])
        interface           = Network._select_interface()
        network_info        = Network._get_ip_and_subnet_mask(interface)
        self._my_ip_address = network_info['ip']
        ip_list             = self._prepare_decoy_and_real_ips(network_info['netmask'])
        self._send_decoy_and_real_packets(ip_list)


    def _prepare_decoy_and_real_ips(self, subnet_mask:str) -> list:
        """ Prepares a list of decoy IPs and adds the real IP to the list."""
        decoy_packets = self._generate_random_ip_in_subnet(self._my_ip_address, subnet_mask)
        return self._add_real_packet(decoy_packets, self._my_ip_address)


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
        real_ip_index = random.randint(packet_number // 2, packet_number - 1)
        decoy_ips.insert(real_ip_index, my_ip)
        return decoy_ips


    def _send_decoy_and_real_packets(self, ip_list:list) -> None:
        """Sends both decoy and real packets to the specified target IP address."""
        for ip in ip_list:
            if ip == self._my_ip_address:
                thread = threading.Thread(target=self._send_real_packet)
                thread.start()
            else:
                self._send_decoy_packet(ip)
            delay = random.uniform(1, 3)
            print(f'{Color.green("Packet sent")}: {ip}, Delay: {delay:.2}')
            time.sleep(delay)


    def _send_real_packet(self) -> None:
        """Sends a real TCP SYN packet to the specified target IP address."""
        real_packet = self._create_tpc_ip_packet(self._ports_to_be_used[0])
        response    = Network._send_single_packet(real_packet)
        self._responses = [(real_packet, response)]


    def _send_decoy_packet(self, decoy_ip:str) -> None:
        """Sends a decoy TCP SYN packet to the specified target IP address."""
        decoy_packet = self._create_tpc_ip_packet(self._ports_to_be_used, decoy_ip)
        send(decoy_packet, verbose=0)


    # PROCESS DATA -------------------------------------------------------------------------------------------
    def _process_responses(self) -> None:
        """Processes the scan responses and displays the results."""
        for sent, received in self._responses:
            port           = sent[TCP].dport
            response_flags = received[TCP].flags if received else None
            description    = self._all_ports[port] if port in self._all_ports else 'Generic Port'
            self._display_result(response_flags, port, description)


    @staticmethod
    def _display_result(response:str|None, port:int, description:str) -> None:
        """Displays the scan result for each port."""
        match response:
            case "SA": status = Color.green('Opened')
            case "S":  status = Color.yellow('Potentially Open')
            case "RA": status = Color.red('Closed')
            case "F":  status = Color.red('Connection Closed')
            case "R":  status = Color.red('Reset')
            case None: status = Color.red('Filtered')
            case _:    status = Color.red('Unknown Status')
        print(f'Status: {status:>17} -> {port:>5} - {description}')
