# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import logging, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import  Ether, ARP, ICMP, IP
from scapy.all import srp, sr1
from scapy.all import conf
from network   import *
from auxiliary import Aux, Argument_Parser_Manager



class Network_Mapper:
    """
    This class performs a network scan using ARP or ICMP (ping).
    It has two scanning methods: one for ARP scanning and one for ping scanning.
    """

    def __init__(self) -> None:
        self._flags     = {'ping': None}
        self._interface = None    # str
        self._network   = None    # ipaddress.IPv4Network


    def _execute(self, database, arguments:list) -> None:
        """Executes the network scan and handles possible errors."""
        try:
            if arguments: self._get_argument_and_flags(database.parser_manager, arguments)
            self._interface = conf.iface = Network._select_interface()
            my_ip_address   = Network._get_ip_address(self._interface)
            subnet_mask     = Network._get_subnet_mask(self._interface)
            self._network   = Network._get_network_information(my_ip_address, subnet_mask)
            self._run_arp_methods() if not self._flags['ping'] else self._run_ping_methods()
        except SystemExit: print(Aux.display_invalid_missing())
        except ValueError: print(Aux.yellow("Invalid IP"))
        except KeyboardInterrupt:  print(Aux.yellow("Process stopped"))
        except Exception as error: print(Aux.display_unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:Argument_Parser_Manager, arguments:list) -> None:
        """Parses arguments and flags from the command line."""
        arguments = parser_manager._parse("Netmapper", arguments)
        self._flags = {'ping': arguments.ping}


    # ARP NETWORK SCANNER METHODS ------------------------------------
    def _run_arp_methods(self) -> None:
        """Performs network scanning using ARP requests."""
        packet   = self._create_arp_packet()
        answered = self._perform_arp_sweep(packet)
        self._display_arp_result(answered)


    def _create_arp_packet(self) -> Ether:
        """Creates an ARP request packet to be sent over the network."""
        arp_request = ARP(pdst=str(self._network))
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
    def _run_ping_methods(self) ->None:
        """Performs network scanning using ICMP ping requests."""
        futures      = self._ping_sweep()
        active_hosts = self._process_result(futures)
        self._display_ping_result(active_hosts)


    def _ping_sweep(self) -> dict:
        """Performs a ping sweep over the network by sending ICMP requests."""
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        conf.verb    = 0
        total_hosts  = self._network.num_addresses - 2
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._send_ping, str(ip)): ip for ip in self._network.hosts()}
            for i, _ in enumerate(as_completed(futures), 1):
                sys.stdout.write(f'\r{Aux.green("Packet sent")}: {i}/{total_hosts}')
                sys.stdout.flush()
        return futures


    @staticmethod
    def _send_ping(ip:str) -> bool:
        """Sends an ICMP ping to the specified IP address using Scapy."""
        packet = IP(dst=ip)/ICMP()
        reply  = sr1(packet, timeout=2, verbose=0)
        return reply is not None


    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
        """Processes the ping responses, collecting active hosts."""
        active_hosts = []
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result(): active_hosts.append(str(ip))
            except Exception as error:
                print(f"{Aux.yellow('Error pinging')} {ip}: {error}")
        return active_hosts


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        """Displays the results of the ping scan, showing active hosts."""
        print('\n')
        for ip in active_hosts:
            print(f'{Aux.green("Active host")}: {ip}')
