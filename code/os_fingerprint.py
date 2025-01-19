# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import asyncio, random
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv    import sr1
from scapy.packet      import Packet, Raw
from auxiliary         import Color, Argument_Parser_Manager


class OS_Fingerprint:
    def __init__(self, parser_manager:Argument_Parser_Manager, data:list) -> None:
        self._parser_manager = parser_manager
        self._data           = data
        self._target_ip      = None
        self._packets        = None
        self._responses      = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            self._get_argument()
            print(f'{Color.yellow("Function still under development")}')
            #self._create_packets()
            #asyncio.run(self._get_responses())
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except ValueError as error: print(Color.display_error(error))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self) -> str:
        arguments       = self._parser_manager._parse("OSFingerprint", self._data)
        self._target_ip = arguments.host


    def _create_packets(self) -> None:
        port_high = random.randint(1024, 65535)
        self._packets = (
            IP(dst=self._target_ip) / ICMP(type=8, code=0),
            IP(dst=self._target_ip) / ICMP(type=13, code=0),
            IP(dst=self._target_ip) / ICMP(type=17, code=0),
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="S"),
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="A", sport=port_high), 
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="F", sport=port_high),
            IP(dst=self._target_ip) / TCP(dport=80, flags="S"),
            IP(dst=self._target_ip) / TCP(dport=80, flags="A", sport=80),
            IP(dst=self._target_ip) / TCP(dport=80, flags="F", sport=80),
            IP(dst=self._target_ip) / UDP(dport=port_high),
            IP(dst=self._target_ip) / UDP(dport=53)
        )


    async def _get_responses(self) -> None:
        with OS_Sending() as responses:
            self._responses = await responses._perform_sending(self._packets)


    def _perform_probes(self) -> None:
        ...



    @staticmethod
    def _icmp_echo_probe(packet:Packet) -> list[str|int|None]:
        if not packet.haslayer(ICMP):
            return ['n', None, None, None, None, None]

        echo_code = packet[ICMP].code       if hasattr(packet[ICMP], 'code') else None,
        ip_id     = packet[IP].id           if hasattr(packet[IP], 'id')     else None
        tos_bits  = packet[IP].tos          if hasattr(packet[IP], 'tos')    else None
        df_bits   = packet[IP].flags == 0x2 if packet[IP].flags is not None  else None
        reply_ttl = packet[IP].ttl          if hasattr(packet[IP], 'ttl')    else None

        return [ 'y', echo_code, ip_id, tos_bits, df_bits, reply_ttl]



    @staticmethod
    def _icmp_timestamp_probe(packet:Packet) -> list[str|int|None]:
        if not packet.haslayer(ICMP) or packet[ICMP].type != 14:
            return ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        return ['y', ttl, ip_id]



    @staticmethod
    def _icmp_addr_mask_probe(packet:Packet) -> list[str|int|None]:
        if not packet.haslayer(ICMP) or packet[ICMP].type != 17:
            return ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        return ['y', ttl, ip_id]



    @staticmethod
    def _icmp_info_probe(packet:Packet) -> list[str|int|None]:
        if not packet.haslayer(ICMP) or packet[ICMP].type != 15:
            return ['n', None, None]

        ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None
        ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None

        return ['y', ttl, ip_id]



    @staticmethod
    def _ip_header_of_the_udp_unreach_probe(packet:Packet) -> list[str|int|None]:
        if not packet.haslayer(ICMP) or packet[ICMP].type != 3:
            return ['n', None, None, None, None, None]

        if packet[ICMP].code == 3:

            echoed_dtsize   = '8' if len(packet[Raw]) == 8 else '64' if len(packet[Raw]) == 64 else '>64'
            reply_ttl       = packet[IP].ttl             if hasattr(packet[IP], 'ttl')         else None
            precedence_bits = hex(packet[IP].precedence) if hasattr(packet[IP], 'precedence')  else None
            df_bits         = packet[IP].flags == 0x2
            ip_id           = packet[IP].id              if hasattr(packet[IP], 'id')          else None

            return ['y', echoed_dtsize, reply_ttl, precedence_bits, df_bits, ip_id]

        return ['n', None, None, None, None, None]



    @staticmethod
    def _original_data_echoed_with_udp_unreach_probe(packet: Packet) -> list:
        if not packet.haslayer(ICMP) or packet[ICMP].type != 3 or packet[ICMP].code != 3:
            return ['n', None, None, None, None]

        ip_layer  = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP) if packet.haslayer(UDP) else None

        udp_cksum   = 'OK' if udp_layer and udp_layer.chksum == 0 else 'BAD'
        ip_cksum    = 'OK' if hasattr(packet[IP], 'chksum') and packet[IP].chksum == 0 else 'BAD'
        ip_id_check = 'OK' if packet[IP].id == ip_layer.id else 'FLIPPED'
        total_len   = 'OK' if len(packet) > 20 else '<20'
        ip_flags    = 'OK' if ip_layer.flags == 0 else 'FLIPPED'

        return ['y', udp_cksum, ip_cksum, ip_id_check, total_len, ip_flags]



    @staticmethod
    def _ip_header_of_the_tcp_syn_ack_probe(packet: Packet) -> list:
        if not packet.haslayer(TCP) or packet[IP].proto != 6:
            return [None, None, None, None]

        if packet[TCP].flags & 0x12 == 0x12:

            tos   = packet[IP].tos if hasattr(packet[IP], 'tos') else None
            df    = packet[IP].flags == 0x2
            ip_id = packet[IP].id  if hasattr(packet[IP], 'id')  else None
            ttl   = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None

            return [tos, df, ip_id, ttl]

        return [None, None, None, None]



    @staticmethod
    def _tcp_header_syn_ack_probe(packet: Packet) -> list:
        if not packet.haslayer(TCP):
            return [None, None, None, None, None, None]

        tcp_syn_ack_ack         = packet[TCP].ack    if hasattr(packet[TCP], 'ack')    else None
        tcp_syn_ack_window_size = packet[TCP].window if hasattr(packet[TCP], 'window') else None

        tcp_syn_ack_options_order = []
        tcp_syn_ack_wscale        = 'NONE'
        tcp_syn_ack_tsval         = 0
        tcp_syn_ack_tsecr         = 0
        if hasattr(packet[TCP], 'options'):
            for option in packet[TCP].options:
                tcp_syn_ack_options_order.append(option[0])
                if option[0] == 'WScale':
                    tcp_syn_ack_wscale = option[1]
                if option[0] == 'Timestamp':
                    if isinstance(option[1], tuple):
                        tcp_syn_ack_tsval, tcp_syn_ack_tsecr = option[1]
                    else:
                        tcp_syn_ack_tsval = option[1]

        return [
            tcp_syn_ack_ack,
            tcp_syn_ack_window_size,
            tcp_syn_ack_options_order,
            tcp_syn_ack_wscale,
            tcp_syn_ack_tsval,
            tcp_syn_ack_tsecr
        ]



    @staticmethod
    def _tcp_rst_ack_probe(packet: Packet) -> list:
        if not packet.haslayer(TCP) or packet[TCP].flags not in ['R', 'A']: 
            return ['n', None, None, None, None, None]

        reply          = 'y' if packet[TCP].flags == 'R' or packet[TCP].flags == 'A' else 'n'
        df             = packet[IP].flags == 0x2
        ip_id_1        = packet[IP].id if hasattr(packet[IP], 'id') else None
        ip_id_2        = packet[IP].id if hasattr(packet[IP], 'id') else None
        ip_id_strategy = 'I' if ip_id_1 == 0 else 'R' if ip_id_2 != 0 else '0'
        ttl            = packet[IP].ttl if hasattr(packet[IP], 'ttl') else None

        return [reply, df, ip_id_1, ip_id_2, ip_id_strategy, ttl]





class OS_Sending: # ==========================================================================================

    def __init__(self):
        self._responses = {
            'icmp_echo':      None,
            'icmp_timestamp': None,
            'icmp_addr_mask': None,
            'tcp_syn1':       None,
            'tcp_ack1':       None,
            'tcp_fin1':       None,
            'tcp_syn2':       None,
            'tcp_ack2':       None,
            'tcp_fin2':       None,
            'udp1':           None,
            'udp2':           None
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    async def _perform_sending(self, packets:list[Packet]) -> dict[Packet]:
        for packet, key in zip(packets, self._responses.keys()):
            await self._get_response(packet, key)
            await asyncio.sleep(random.uniform(0.5, 2))
        return self._responses


    async def _get_response(self, packet:Packet, key:str) -> None:
        self._responses[key] = sr1(packet, timeout=5, verbose=0)
