# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all         import conf, get_if_addr, Packet
from scapy.layers.l2   import Ether, ARP
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv    import srp, sr
from arg_parser        import Argument_Manager as ArgParser
from network           import *
from display           import *


class Network_Mapper:

    def __init__(self, parser_manager:ArgParser) -> None:
        self._flags:dict = None
        self._my_ip:str  = get_if_addr(conf.iface)
        self._get_argument_and_flags(parser_manager)


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            if self._flags['ping']: self._ping_sweep()
            else:                   self._run_arp_methods()
        except KeyboardInterrupt:   print(yellow("Process stopped"))
        except ValueError as error: print(yellow(error))
        except Exception as error:  print(unexpected_error(error))


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._flags = {'ping': parser_manager.ping}

    # PACKETS -------------------------------------------------------------------------

    def _get_arp_packet(self) -> Packet:
        return Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(op=1, pdst=self._my_ip)
    
    def _get_ping_packet(self, target_ip:ipaddress) -> Packet:
        return IP(dst=target_ip) / ICMP()


    # ARP -----------------------------------------------------------------------------
    def _run_arp_methods(self) -> None:
        packet       = self._get_arp_packet()
        responses, _ = srp(packet, timeout=2, verbose=False)
        self._display_arp_result(responses)


    @staticmethod
    def _display_arp_result(responses:list[Packet]) -> None:
        for _, answered in responses:
            print(f'{green("Active host")}: IP {answered.psrc:<15}, MAC {answered.hwsrc}')


    # PING ---------------------------------------------------------------------------

    def _ping_sweep(self) -> None:
        packets   = self._create_packets()
        responses = list() 
        for pkt_sublist in packets:
            received, _ = sr(pkt_sublist, timeout=5, verbose=0)
            responses.append(received[-1])
        print('ok')
        self._display_ping_result(responses)


    def _create_packets(self) -> list[list[Packet]]:
        packet_list = [self._get_ping_packet(str(ip)) for ip in self._get_ip_list()]
        return self._calculate_max_packets(packet_list)


    def _get_ip_list(self) -> list[ipaddress.IPv4Address]:
        netmask = get_subnet_mask(str(conf.iface))
        return get_ip_range(self._my_ip, netmask)


    def _calculate_max_packets(self, packet_list:list[Packet]) -> list[list[Packet]]:
        half_buffer_size = get_buffer_size() // 2
        max_packets      = half_buffer_size // 84
        packet_sublists  = list()
        while packet_list:
            packet_sublists.append(packet_list[:max_packets])
            packet_list = packet_list[max_packets:]
        return packet_sublists


    @staticmethod
    def _display_ping_result(active_hosts:list) -> None:
        print('\n')
        for ip in active_hosts:
            print(f'{green("Active host")}: {ip}')