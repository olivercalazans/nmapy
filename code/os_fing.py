# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import asyncio, random, os
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.packet      import Raw
from arg_parser        import Argument_Manager as ArgParser
from os_fing_sendings  import OS_Sending
from display           import *


class OS_Fingerprint:

    def __init__(self, parser_manager:ArgParser) -> None:
        self._target_ip      = None
        self._os_database    = dict()
        self._packets        = None
        self._responses      = None
        self._probes_info    = list()
        self._get_argument(parser_manager)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            #print(f'{Color.yellow("Function still under development")}')
            self._read_database()
            self._create_packets()
            asyncio.run(self._get_responses())
            self._perform_probes()
            self._display_result()
        except KeyboardInterrupt:  print(red("Process stopped"))
        except FileNotFoundError:  print('os_db.txt not found')
        except Exception as error: print(unexpected_error(error))


    def _get_argument(self, parser_manager:ArgParser) -> str:
        self._target_ip = parser_manager.host

    
    def _read_database(self) -> None:
        FILE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/os_db.txt'
        with open(FILE_PATH, 'r') as file:
            for line in file:
                key, value = line.split(':')
                self._os_database[eval(key)] = value


    def _create_packets(self) -> None:
        port_high     = random.randint(1024, 65535)
        IP_LAYER      = IP(dst=self._target_ip)
        OPEN_PORT     = 22
        self._packets = (
            IP_LAYER / ICMP(),
            IP_LAYER / ICMP(type=13),
            IP_LAYER / ICMP(type=17),
            IP_LAYER / ICMP(type=15),
            IP_LAYER / UDP(dport=port_high),
            IP_LAYER / TCP(dport=OPEN_PORT, flags="S"),
            IP_LAYER / TCP(dport=OPEN_PORT, flags="R")
        )


    async def _get_responses(self) -> None:
        with OS_Sending() as responses:
            self._responses = await responses._perform_sending(self._packets)


    # PROBES -------------------------------------------------------------------------------------------------
    def _perform_probes(self) -> None:
        self._icmp_echo_probe()
        self._icmp_timestamp_probe()
        self._icmp_addr_mask_probe()
        self._icmp_info_probe()
        self._udp_unreach_header_probe()
        self._udp_unreach_probe()
        self._tcp_syn_ack_probe()
        self._tcp_header_syn_ack_probe()
        self._tcp_rst_ack_probe()



    def _icmp_echo_probe(self) -> None:
        packet = self._responses['icmp_echo']
        print(packet)

        if not packet.haslayer(ICMP):
            self._probes_info += ['n', None, None, None, None, None]

        echo_code = packet[ICMP].code       if hasattr(packet[ICMP], 'code') else None,
        ip_id     = packet[IP].id           if hasattr(packet[IP], 'id')     else None
        tos_bits  = packet[IP].tos          if hasattr(packet[IP], 'tos')    else None
        df_bits   = packet[IP].flags == 0x2 if packet[IP].flags is not None  else None
        reply_ttl = packet[IP].ttl          if hasattr(packet[IP], 'ttl')    else None

        self._probes_info += ['y', echo_code, ip_id, tos_bits, df_bits, reply_ttl]



    def _icmp_timestamp_probe(self) -> None:
        packet = self._responses['icmp_timestamp']
        print(packet)

        if not packet.haslayer(ICMP) or packet[ICMP].type != 14:
            self._probes_info += ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        self._probes_info += ['y', ttl, ip_id]



    def _icmp_addr_mask_probe(self) -> None:
        packet = self._responses['icmp_addr_mask']
        print(packet)

        if not packet.haslayer(ICMP) or packet[ICMP].type != 17:
            self._probes_info += ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        self._probes_info += ['y', ttl, ip_id]



    def _icmp_info_probe(self) -> None:
        packet = self._responses['icmp_info']
        print(packet)

        if not packet.haslayer(ICMP) or packet[ICMP].type != 15:
            self._probes_info += ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        self._probes_info += ['y', ttl, ip_id]



    def _udp_unreach_header_probe(self) -> None:
        packet = self._responses['udp']
        print(packet)

        if not packet.haslayer(ICMP) or packet[ICMP].type != 3:
            self._probes_info += ['n', None, None, None, None, None]

        if packet[ICMP].code == 3:

            echoed_dtsize   = '8' if len(packet[Raw]) == 8 else '64' if len(packet[Raw]) == 64 else '>64'
            reply_ttl       = packet[IP].ttl             if hasattr(packet[IP], 'ttl')         else None
            precedence_bits = hex(packet[IP].precedence) if hasattr(packet[IP], 'precedence')  else None
            df_bits         = packet[IP].flags == 0x2
            ip_id           = packet[IP].id              if hasattr(packet[IP], 'id')          else None

            self._probes_info += ['y', echoed_dtsize, reply_ttl, precedence_bits, df_bits, ip_id]

        self._probes_info += ['n', None, None, None, None, None]



    def _udp_unreach_probe(self) -> None:
        packet = self._responses['udp']
        print(packet)

        if not packet.haslayer(ICMP) or packet[ICMP].type != 3 or packet[ICMP].code != 3:
            self._probes_info += ['n', None, None, None, None]

        ip_layer  = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP) if packet.haslayer(UDP) else None

        udp_cksum   = 'OK' if udp_layer and udp_layer.chksum == 0 else 'BAD'
        ip_cksum    = 'OK' if hasattr(packet[IP], 'chksum') and packet[IP].chksum == 0 else 'BAD'
        ip_id_check = 'OK' if packet[IP].id == ip_layer.id else 'FLIPPED'
        total_len   = 'OK' if len(packet) > 20 else '<20'
        ip_flags    = 'OK' if ip_layer.flags == 0 else 'FLIPPED'

        self._probes_info += ['y', udp_cksum, ip_cksum, ip_id_check, total_len, ip_flags]



    def _tcp_syn_ack_probe(self) -> None:
        packet = self._responses['tcp_syn']
        print(packet)

        if not packet.haslayer(TCP) or packet[IP].proto != 6:
            self._probes_info += [None, None, None, None]

        if packet[TCP].flags & 0x12 == 0x12:

            tos   = packet[IP].tos if hasattr(packet[IP], 'tos') else None
            df    = packet[IP].flags == 0x2
            ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None
            ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None

            self._probes_info += [tos, df, ip_id, ttl]

        self._probes_info += [None, None, None, None]



    def _tcp_header_syn_ack_probe(self) -> None:
        packet = self._responses['tcp_syn']
        print(packet)

        if not packet.haslayer(TCP):
            self._probes_info += [None, None, None, None, None, None]

        ack         = packet[TCP].ack    if hasattr(packet[TCP], 'ack')    else None
        window_size = packet[TCP].window if hasattr(packet[TCP], 'window') else None

        options_order = []
        wscale        = 'NONE'
        tsval         = 0
        tsecr         = 0
        if hasattr(packet[TCP], 'options'):
            for option in packet[TCP].options:
                options_order.append(option[0])
                if option[0] == 'WScale':
                    wscale = option[1]
                if option[0] == 'Timestamp':
                    if isinstance(option[1], tuple):
                        tsval, tsecr = option[1]
                    else:
                        tsval = option[1]

        self._probes_info += [ack, window_size, options_order, wscale, tsval, tsecr]



    def _tcp_rst_ack_probe(self) -> list:
        packet = self._responses['tcp_rst']
        print(packet)

        if not packet.haslayer(TCP) or packet[TCP].flags not in ['R', 'A']: 
            self._probes_info += ['n', None, None, None, None, None]

        reply          = 'y' if packet[TCP].flags == 'R' or packet[TCP].flags == 'A' else 'n'
        df             = packet[IP].flags == 0x2
        ip_id_1        = packet[IP].id if hasattr(packet[IP], 'id') else None
        ip_id_2        = packet[IP].id if hasattr(packet[IP], 'id') else None
        ip_id_strategy = 'I' if ip_id_1 == 0 else 'R' if ip_id_2 != 0 else '0'
        ttl            = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None

        self._probes_info += [reply, df, ip_id_1, ip_id_2, ip_id_strategy, ttl]

    
    # DISPLAY ------------------------------------------------------------------------------------------------
    def _display_result(self) -> None:
        result = self._os_database.get(tuple(self._probes_info), None)
        if not result: print('No maching results')
        else:          print(result)