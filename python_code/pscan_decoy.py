# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random, threading, time
from scapy.all         import conf, get_if_addr
from scapy.layers.inet import IP, TCP
from scapy.sendrecv    import sr1, send
from scapy.packet      import Packet
from network           import *


class Decoy:

    def __init__(self, target_ip, port):
        self._target_ip:str   = target_ip
        self._port:int        = port
        self._netmask:str     = get_subnet_mask(conf.iface)
        self._my_ip:str       = get_if_addr(conf.iface)
        self._decoy_ips:list  = None
        self._response:Packet = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _perform_decoy_methods(self) -> Packet:
        self._generate_random_ip_in_subnet()
        self._add_real_packet()        
        self._send_decoy_and_real_packets()
        return self._response


    def _generate_random_ip_in_subnet(self, count = random.randint(4, 6)) -> None:
        network         = ipaddress.IPv4Network(f"{self._my_ip}/{self._netmask}", strict=False)
        hosts           = list(network.hosts())
        random_ips      = random.sample(hosts, count)
        self._decoy_ips = [str(ip) for ip in random_ips]


    def _add_real_packet(self) -> list:
        packet_number = len(self._decoy_ips)
        real_ip_index = random.randint(packet_number // 2, packet_number - 1)
        self._decoy_ips.insert(real_ip_index, self._my_ip)


    def _send_decoy_and_real_packets(self) -> None:
        for ip in self._decoy_ips:
            delay = random.uniform(1, 3)
            if ip == self._my_ip:
                print(f'{green("Real packet")}: {ip:<15}, Delay: {delay:.2}')
                thread = threading.Thread(target=self._send_real_packet)
                thread.start()
            else:
                print(f'{red("Decoy packet")}: {ip:<15}, Delay: {delay:.2}')
                self._send_decoy_packet(ip)
            time.sleep(delay)


    def _send_real_packet(self) -> None:
        real_packet    = self._create_tcp_packet(self._my_ip)
        response       = sr1(real_packet, timeout=3, verbose=0)
        self._response = [(real_packet, response)]


    def _send_decoy_packet(self, decoy_ip:str) -> None:
        decoy_packet = self._create_tcp_packet(decoy_ip)
        send(decoy_packet, verbose=0)


    def _create_tcp_packet(self, source_ip:str) -> Packet:
        return IP(dst=self._target_ip, src=source_ip) / TCP(dport=self._port, flags="S")