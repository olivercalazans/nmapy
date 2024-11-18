# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import logging, sys, signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import conf
from network   import Network
from auxiliary import Color, Argument_Parser_Manager


class Network_Mapper:
    """
    This class performs a network scan using ARP or ICMP (ping).
    It has two scanning methods: one for ARP scanning and one for ping scanning.
    """

    def __init__(self) -> None:
        self._flags     = {'ping': False}
        self._interface = None    # str
        self._network   = None    # ipaddress.IPv4Network


    def _execute(self, database, arguments:list) -> None:
        """Executes the network scan and handles possible errors."""
        try:
            if arguments: self._get_argument_and_flags(database.parser_manager, arguments)
            self._interface = conf.iface = Network._select_interface()
            network_info    = Network._get_ip_and_subnet_mask(self._interface)
            self._network   = Network._get_network_information(network_info['ip'], network_info['netmask'])
            self._run_arp_methods() if not self._flags['ping'] else self._run_ping_methods()
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except ValueError as error: print(Color.yellow(error))
        except KeyboardInterrupt:   print(Color.yellow("Process stopped"))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:Argument_Parser_Manager, arguments:list) -> None:
        """Parses arguments and flags from the command line."""
        arguments = parser_manager._parse("Netmapper", arguments)
        self._flags = {'ping': arguments.ping}


    # ARP NETWORK SCANNER METHODS -----------------------------------------------------------------------------
    def _run_arp_methods(self) -> None:
        """Performs network scanning using ARP requests."""
        packet   = Network._create_arp_packet(self._network)
        answered = Network._send_and_receive_layer2_packet(packet)
        self._display_arp_result(answered)


    @staticmethod
    def _display_arp_result(answered:list[tuple]) -> None:
        """Displays the results of the ARP scan, showing active hosts."""
        for _, received in answered:
            print(f'{Color.green("Active host")}: IP {received.psrc:<15}, MAC {received.hwsrc}')


    # PING NETWORK SCANNER METHODS -------------------------------------------------------------------------
    def _run_ping_methods(self) -> None:
        """Performs network scanning using ICMP ping requests."""
        futures = self._ping_sweep()
        active_hosts = self._process_result(futures)
        self._display_ping_result(active_hosts)


    def _ping_sweep(self) -> dict:
        """Performs a ping sweep over the network by sending ICMP requests."""
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        conf.verb = 0
        total_hosts = self._network.num_addresses - 2
        with ThreadPoolExecutor(max_workers=100) as executor:
            signal.signal(signal.SIGINT, lambda signum, frame: self._handle_interrupt(signum, frame, executor))
            futures = self._create_ping_tasks(executor)
            try:   self._process_ping_tasks(futures, total_hosts, executor)
            except Exception: executor.shutdown(wait=False, cancel_futures=True)
        return futures


    def _create_ping_tasks(self, executor:ThreadPoolExecutor) -> dict:
        """Creates ping tasks for each host in the network."""
        return {executor.submit(self._send_ping, str(ip)): ip for ip in self._network.hosts()}


    def _process_ping_tasks(self, futures:dict, total_hosts:int, executor:ThreadPoolExecutor) -> None:
        """Processes the results of ping tasks as they complete."""
        for i, _ in enumerate(as_completed(futures), 1):
            if executor._shutdown: break
            self._update_progress(i, total_hosts)


    @staticmethod
    def _update_progress(current:int, total:int) -> None:
        """Updates progress in the console."""
        sys.stdout.write(f'\r{Color.green("Packet sent")}: {current}/{total}')
        sys.stdout.flush()


    @staticmethod
    def _send_ping(ip:str) -> bool:
        """Sends an ICMP ping to the specified IP address using Scapy."""
        packet = Network._create_icmp_ip_packet(ip)
        reply  = Network._send_and_receive_single_layer3_packet(packet)
        return reply is not None


    @staticmethod
    def _handle_interrupt(signum, frame, executor:ThreadPoolExecutor):
        """Handles user interrupt (Ctrl + C) to stop threads gracefully."""
        print("\nInterrupted by user. Shutting down threads...")
        executor.shutdown(wait=False, cancel_futures=True)


    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
        """Processes the ping responses, collecting active hosts."""
        active_hosts = []
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result(): active_hosts.append(str(ip))
            except Exception:
                continue
        return active_hosts


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        """Displays the results of the ping scan, showing active hosts."""
        print('\n')
        for ip in active_hosts:
            print(f'{Color.green("Active host")}: {ip}')
