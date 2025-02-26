# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import logging, sys, signal
from scapy.all          import conf, get_if_addr, Packet
from scapy.layers.l2    import Ether, ARP
from scapy.layers.inet  import IP, ICMP
from scapy.sendrecv     import sr1, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
from arg_parser         import Argument_Manager as ArgParser
from network            import *
from display            import *


class Network_Mapper:

    def __init__(self, parser_manager:ArgParser) -> None:
        self._flags:dict = None
        self._network    = None
        self._get_argument_and_flags(parser_manager)


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            my_ip:str     = get_if_addr(conf.iface)
            netmask:str   = get_subnet_mask(str(conf.iface))
            self._network = get_network_information(my_ip, netmask)
            if self._flags['ping']: self._run_ping_methods()
            else:                   self._run_arp_methods(my_ip)
        except KeyboardInterrupt:   print(yellow("Process stopped"))
        except ValueError as error: print(yellow(error))
        except Exception as error:  print(unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._flags = {'ping': parser_manager.ping}


    # ARP -----------------------------------------------------------------------------
    def _run_arp_methods(self, my_ip:str) -> None:
        packet       = Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(op=1, pdst=my_ip)
        responses, _ = srp(packet, timeout=2, verbose=False)
        self._display_arp_result(responses)


    @staticmethod
    def _display_arp_result(responses:list[Packet]) -> None:
        for _, answered in responses:
            print(f'{green("Active host")}: IP {answered.psrc:<15}, MAC {answered.hwsrc}')


    # PING ---------------------------------------------------------------------------
    def _run_ping_methods(self) -> None:
        futures = self._ping_sweep()
        active_hosts = self._process_result(futures)
        self._display_ping_result(active_hosts)


    def _ping_sweep(self) -> dict:
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
        return {executor.submit(self._send_ping, str(ip)): ip for ip in self._network.hosts()}


    def _process_ping_tasks(self, futures:dict, total_hosts:int, executor:ThreadPoolExecutor) -> None:
        for i, _ in enumerate(as_completed(futures), 1):
            if executor._shutdown: break
            self._update_progress(i, total_hosts)


    @staticmethod
    def _update_progress(current:int, total:int) -> None:
        sys.stdout.write(f'\r{green("Packets sent")}: {current}/{total}')
        sys.stdout.flush()


    @staticmethod
    def _send_ping(ip:str) -> bool:
        packet = IP(dst=ip) / ICMP()
        reply  = sr1(packet, timeout=3, verbose=0)
        return reply is not None


    @staticmethod
    def _handle_interrupt(signum, frame, executor:ThreadPoolExecutor):
        print("\nInterrupted by user. Shutting down threads...")
        executor.shutdown(wait=False, cancel_futures=True)


    @staticmethod
    def _process_result(future_to_ip:dict) -> list:
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
        print('\n')
        for ip in active_hosts:
            print(f'{green("Active host")}: {ip}')