# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import ipaddress, logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import  Ether, ARP, ICMP, IP
from scapy.all import srp, sr1
from scapy.all import conf
from auxiliary import Aux, Argument_Parser_Manager, Network



class Network_Scanner:
    """
    This class performs a network scan using ARP or ICMP (ping).
    It has two scanning methods: one for ARP scanning and one for ping scanning.
    """

    @staticmethod
    def _execute(database, arguments:list) -> None:
        """Executes the network scan and handles possible errors."""
        try:
            ping       = None if not arguments else Network_Scanner._get_argument_and_flags(database.parser_manager, arguments)
            interface  = Network._select_interface()
            conf.iface = interface
            network    = Network._get_network_information(Network._get_ip_address(interface), Network._get_subnet_mask(interface))
            Network_Scanner._run_arp_methods(network) if not ping else Network_Scanner._run_ping_methods(network)
        except SystemExit: print(Aux.display_invalid_missing())
        except ValueError: print(Aux.yellow("Invalid IP"))
        except KeyboardInterrupt:  print(Aux.orange("Process stopped"))
        except Exception as error: print(Aux.display_unexpected_error(error))


    @staticmethod
    def _get_argument_and_flags(parser_manager:Argument_Parser_Manager, arguments:list) -> tuple[str, bool]:
        """Parses arguments and flags from the command line."""
        arguments = parser_manager._parse("Netscanner", arguments)
        return arguments.ping


    # ARP NETWORK SCANNER METHODS ------------------------------------
    @staticmethod
    def _run_arp_methods(network:ipaddress.IPv4Network) -> None:
        """Performs network scanning using ARP requests."""
        packet   = Network_Scanner._create_arp_packet(network)
        answered = Network_Scanner._perform_arp_sweep(packet)
        Network_Scanner._display_arp_result(answered)


    @staticmethod
    def _create_arp_packet(network:ipaddress.IPv4Network) -> Ether:
        """Creates an ARP request packet to be sent over the network."""
        arp_request = ARP(pdst=str(network))
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        return broadcast / arp_request


    @staticmethod
    def _perform_arp_sweep(packet:Ether) -> list:
        """Sends the ARP packet and returns a list of answered responses."""
        answered, _ = srp(packet, timeout=2, verbose=False)
        return answered


    @staticmethod
    def _display_arp_result(answered:list[tuple]) -> None:
        """Displays the results of the ARP scan, showing active hosts."""
        for _, received in answered:
            print(f'{Aux.green("Active host")}: IP {received.psrc:<15}, MAC {received.hwsrc}')


    # PING NETWORK SCANNER METHODS -----------------------------------
    @staticmethod
    def _run_ping_methods(network:ipaddress.IPv4Network) ->None:
        """Performs network scanning using ICMP ping requests."""
        futures      = Network_Scanner._ping_sweep(network)
        active_hosts = Network_Scanner._process_result(futures)
        Network_Scanner._display_ping_result(active_hosts)


    @staticmethod
    def _ping_sweep(network:ipaddress.IPv4Network) -> dict:
        """Performs a ping sweep over the network by sending ICMP requests."""
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        conf.verb = 0
        with ThreadPoolExecutor(max_workers=100) as executor:
            return {executor.submit(Network_Scanner._send_ping, str(ip)): ip for ip in network.hosts()}


    @staticmethod
    def _send_ping(ip: str) -> bool:
        """Sends an ICMP ping to the specified IP address using Scapy."""
        packet = IP(dst=ip)/ICMP()
        reply  = sr1(packet, timeout=2, verbose=0)
        return reply is not None


    # PROCESS RESULT -----------------------------------------------------------------------------------------
    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
        """Processes the ping responses, collecting active hosts."""
        active_hosts = []
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result(): active_hosts.append(str(ip))
            except Exception as error:
                print(f"{Aux.orange('Error pinging')} {ip}: {error}")
        return active_hosts


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        """Displays the results of the ping scan, showing active hosts."""
        for ip in active_hosts:
            print(f'{Aux.green("Active host")}: {ip}')
