# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


"""
THIS FILE CONTAINS THE CLASSES THAT EXECUTE COMMANDS.
"""


import socket, ipaddress, subprocess, platform, json, urllib.request, re
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, ARP, Ether
from scapy.all import sr, srp
from scapy.all import conf
from auxiliary import Aux, Argument_Parser_Manager




class Command_List: # ========================================================================================
    """Displays a list of all available commands."""

    def _execute(self, __, _) -> None:
        for i in (
            f'{Aux.green("ip")}........: Get IP by name',
            f'{Aux.green("geoip")}.....: Get geolocation of an IP',
            f'{Aux.green("pscan")}.....: Port scanner',
            f'{Aux.green("netscan")}...: Network scanner',
            f'{Aux.green("macdev")}....: Looks up a MAC'
        ): print(i)





class Network: # =============================================================================================
    """Contains common network-related methods used by multiple classes."""

    @staticmethod
    def _get_ip_by_name(hostname:str) -> str:
        """Get the IP address of a given hostname."""
        try:    ip = socket.gethostbyname(hostname)
        except: ip = Aux.display_error(f'Invalid hostname ({hostname})')
        return  ip





class Get_IP: # ==============================================================================================
    """Performs a lookup and displays the IP address of a hostname."""

    def _execute(self, auxiliary_data, data:list) -> None:
        """Executes the process to retrieve the IP address based on the provided hostname."""
        try:   argument = self._get_argument(auxiliary_data.parser_manager, data)
        except SystemExit:         print(Aux.display_error("Invalid/missing argument"))
        except Exception as error: print(Aux.display_unexpected_error(error))
        else:  self._ip(argument)


    @staticmethod
    def _get_argument(parser_manager:Argument_Parser_Manager, argument:list) -> str:
        """Parses and retrieves the hostname argument."""
        arguments = parser_manager._parse("Get_Ip", argument)
        return (arguments.host)


    @staticmethod
    def _ip(host_name:str) -> None:
        """Displays the IP address of the provided hostname."""
        print(Network._get_ip_by_name(host_name))





class Port_Scanner: # ========================================================================================
    """Performs a port scan on a specified host."""

    def _execute(self, auxiliary_data, data:list) -> None:
        """ Executes the port scanning process with error handling."""
        try:
            host, port, verb = self._get_argument_and_flags(auxiliary_data.parser_manager, data)
            port_dictionary  = self._prepare_ports(port)
            target_ip        = Network._get_ip_by_name(host)
            packages         = self._create_packages(target_ip, port_dictionary, verb)
            responses, _     = self._send_packages(packages)
            self._process_responses(responses, port_dictionary)
        except SystemExit:          print(Aux.display_invalid_missing())
        except socket.gaierror:     print(Aux.display_error('An error occurred in resolving the host'))
        except socket.error:        print(Aux.display_error(f'It was not possible to connect to "{host}"'))
        except Exception as error:  print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> tuple:
        """Parses and retrieves the hostname, port, and verbosity flag from the arguments."""
        arguments = parser_manager._parse("PortScanner", data)
        return (arguments.host, arguments.port, arguments.verbose)


    def _prepare_ports(self, port:int) -> dict:
        """Prepares the port or ports to be scanned."""
        return self._get_ports() if port == None else {port: None}


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
    def _create_packages(ip:str, ports:dict, verbose:bool) -> list:
        """Creates the TCP SYN packets to be sent for scanning the specified ports."""
        conf.verb = 0 if not verbose else 1
        return [IP(dst=ip)/TCP(dport=port, flags="S") for port in ports.keys()]


    @staticmethod
    def _send_packages(packages:list) -> tuple[list, list]:
        """Sends the SYN packets and receives the responses."""
        responses, unanswered = sr(packages, timeout=5, inter=0.1)
        return (responses, unanswered)


    def _process_responses(self, responses:list, ports:dict) -> None:
        """Processes the scan responses and displays the results."""
        for sent, received in responses:
            port           = sent[TCP].dport
            response_flags = received[TCP].flags if received else None
            description    = ports[port] if port in self._get_ports() else 'Generic Port'
            self._display_result(response_flags, port, description)


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





class Network_Scanner: # =====================================================================================
    """
    This class performs a network scan using ARP or ICMP (ping).
    It has two scanning methods: one for ARP scanning and one for ping scanning.
    """

    def _execute(self, auxiliary_data, data:list) -> None:
        """Executes the network scan and handles possible errors."""
        try:   
            ip, ping    = self._get_argument_and_flags(auxiliary_data.parser_manager, data)
            network     = self._get_network(ip)
            self._run_arp_methods(network) if not ping else self._run_ping_methods(network)
        except SystemExit: print(Aux.display_invalid_missing())
        except ValueError: print(Aux.yellow("Invalid IP"))
        except KeyboardInterrupt:  print(Aux.orange("Process stopped"))
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> tuple[str, bool]:
        """Parses arguments and flags from the command line."""
        arguments = parser_manager._parse("Netscanner", data)
        return (arguments.ip, arguments.ping)


    @staticmethod
    def _get_network(ip:str) -> ipaddress.IPv4Network:
        """Returns the network to be scanned, based on the provided IP address."""
        return ipaddress.ip_network(f'{ip}/24', strict=False)


    # ARP NETWORK SCANNER METHODS ------------------------------------
    def _run_arp_methods(self, network:ipaddress.IPv4Network) -> None:
        """Performs network scanning using ARP requests."""
        package  = self._create_arp_package(network)
        answered = self._perform_arp_sweep(package)
        self._display_arp_result(answered)


    @staticmethod
    def _create_arp_package(network:ipaddress.IPv4Network) -> Ether:
        """Creates an ARP request package to be sent over the network."""
        arp_request = ARP(pdst=str(network))
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        return broadcast / arp_request


    @staticmethod
    def _perform_arp_sweep(package:Ether) -> list:
        """Sends the ARP package and returns a list of answered responses."""
        answered, _ = srp(package, timeout=2, verbose=False)
        return answered


    @staticmethod
    def _display_arp_result(answered:list[tuple]) -> None:
        """Displays the results of the ARP scan, showing active hosts."""
        for _, received in answered:
            print(f'{Aux.green("Active host")}: IP {received.psrc:<15}, MAC {received.hwsrc}')


    # PING NETWORK SCANNER METHODS -----------------------------------
    def _run_ping_methods(self, network:ipaddress.IPv4Network) ->None:
        """Performs network scanning using ICMP ping requests."""
        futures      = self._ping_sweep(network)
        active_hosts = self._process_result(futures)
        self._display_ping_result(active_hosts)


    def _ping_sweep(self, network:ipaddress.IPv4Network) -> dict:
        """Performs a ping sweep over the network by sending ICMP requests."""
        with ThreadPoolExecutor(max_workers=100) as executor:
            return {executor.submit(self._send_ping, str(ip)): ip for ip in network.hosts()}


    def _send_ping(self, ip:str) -> bool:
        """Sends an ICMP ping to the specified IP address."""
        command = self._prepare_ping_command(ip)
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


    @staticmethod
    def _prepare_ping_command(ip:str) -> list:
        """Prepares the ping command based on the operating system."""
        flag = '-n' if platform.system() == 'Windows' else '-c'        
        return ['ping', flag, '1', str(ip)]


    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
        """Processes the ping responses, collecting active hosts."""
        active_hosts = []
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_hosts.append(str(ip))
            except Exception as error:
                print(f"{Aux.orange('Error pinging')} {ip}: {error}")
        return active_hosts


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        """Displays the results of the ping scan, showing active hosts."""
        for ip in active_hosts:
            print(f'{Aux.green("Active host")}: {ip}')





class IP_Geolocation: # ======================================================================================
    """This class performs the geolocation of an IP address."""

    def _execute(self, auxiliary_data, data:list) -> None:
        """Executes the geolocation process and handles errors."""
        try:
            host   = self._get_argument_and_flags(auxiliary_data.parser_manager, data)
            ip     = Network._get_ip_by_name(host)
            data   = self._get_geolocation(ip)
            result = self._process_data(data)
            self._display_result(result)
        except SystemExit: print(Aux.display_invalid_missing())
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> str:
        """Parses arguments and returns the IP address as a string."""
        arguments = parser_manager._parse("GeoIP", data)
        return (arguments.ip)
    
    
    @staticmethod
    def _get_geolocation(ip:ipaddress.IPv4Address) -> dict:
        """Fetches the geolocation information for the given IP address from a web service."""
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json") as response:
            return json.load(response)

    
    @staticmethod
    def _process_data(data:object) -> dict:
        """Processes the geolocation data and extracts specific fields."""
        return {
                "IP":       data.get("ip"),
                "City":     data.get("city"),
                "Region":   data.get("region"),
                "Country":  data.get("country"),
                "Location": data.get("loc"),
                "Postal":   data.get("postal"),
                "Timezone": data.get("timezone")
            }


    @staticmethod
    def _display_result(result:dict) -> None:
        """Displays the processed geolocation results in a formatted manner."""
        for key, value in result.items():
            separator = (8 - len(key)) * '.'
            print(f'{key}{separator}: {value}')





class MAC_To_Device: # =======================================================================================
    """This class displays the manufacturer of devices based on their MAC address."""

    def _execute(self, auxiliary_data, argument:list) -> None:
        """Executes the manufacturer lookup process and handles errors."""
        try: 
            mac    = self._get_argument_and_flags(auxiliary_data.parser_manager, argument)
            mac    = self._normalize_mac(mac)
            result = self._lookup_mac(auxiliary_data.mac_dictionary, mac)
            self._display_result(mac, result)
        except SystemExit: print(Aux.display_invalid_missing())
        except ValueError as error: print(Aux.display_error(error))
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, data:list) -> str:
        """Parses arguments and returns the normalized MAC address as a string."""
        arguments = parser_manager._parse("MacToDev", data)
        return (arguments.mac)
    

    @staticmethod
    def _normalize_mac(mac):
        """Validates the MAC address and returns it in a normalized format."""
        cleaned_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
        if len(cleaned_mac) < 6: raise ValueError("Invalid MAC address")
        normalized_mac = '-'.join([cleaned_mac[i:i+2] for i in range(0, 6, 2)])
        return normalized_mac.upper()


    @staticmethod
    def _lookup_mac(mac_dictionary:list[dict], mac:str) -> None:
        """Looks up the manufacturer associated with the provided MAC address."""
        return mac_dictionary.get(mac, 'Not found')
        

    @staticmethod
    def _display_result(mac:str, result:str) -> None:
        """Displays the manufacturer information based on the MAC address."""
        print(f'MAC: {mac} - Manufacturer: {result}')
