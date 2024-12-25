# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading
from scapy.all import ICMP, IP, TCP, Raw, Packet
from math      import gcd, log2
from functools import reduce
from time      import perf_counter, sleep
from network   import Network
from auxiliary import Argument_Parser_Manager, Color


class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip   = None
        self._open_port   = None
        self._closed_port = None
        self._WRAP_LIMIT  = 2 ** 32
        self._lock        = threading.Lock()
        self._diff1       = list()
        self._isns        = list()
        self._times       = list()
        self._gcd         = None
        self._seq_rates   = list()
        self._isr         = None


    def _execute(self, database, data:list) -> None:
        """Executes the fingerprinting process on the provided data."""
        try:
            self._get_argument(database.parser_manager, data)
            print('function still under development')
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self, parser_manager:Argument_Parser_Manager, argument:list) -> str:
        """Parses and retrieves the target IP address from the provided arguments."""
        arguments = parser_manager._parse("OSFingerprint", argument)
        self._target_ip = arguments.target


    # PACKETS ================================================================================================

    # Sequence generation (SEQ, OPS, WIN, and T1) ------------------------------------------------------------
    def _get_sequence_generation_packets(self) -> Packet:
        return (
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=1,   options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b''),]),
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=63,  options=[('MSS', 1400),  ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=4,   options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]),
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=4,   options=[('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=16,  options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=self._target_ip) / TCP(dport=self._open_port, window=512, options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))])
        )


    # ICMP echo (IE) -----------------------------------------------------------------------------------------
    def _get_icmp_echo_packets(self) -> Packet:
        return (
            IP(dst=self._target_ip, tos=0, flags='DF') / ICMP(type=8, code=9, id=12345, seq=295) / Raw(load=b'\x00' * 120),
            IP(dst=self._target_ip, tos=4)       /       ICMP(type=8, code=0, id=12346, seq=296) / Raw(load=b'\x00' * 150)
            )


    # TCP explicit congestion notification (ECN) -------------------------------------------------------------
    def _get_ecn_syn_packet(self) -> Packet:
        TCP_OPTIONS        = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SACKOK', b''), ('NOP', None), ('NOP', None)]
        packet             = IP(dst=self._target_ip) / TCP(dport=self._open_port, flags="S", window=3, options=TCP_OPTIONS)
        packet[TCP].flags |= 0x18    # 0x18 = CWR (0b00010000) + ECE (0b00001000)
        return packet


    # TCP (T2–T7) --------------------------------------------------------------------------------------------
    def _get_t2_through_t7_tcp_packets(self) -> Packet:
        COMMON_TCP_OPTIONS        = [('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')]
        COMMOM_WSCALE_AND_OPTIONS = [('WScale', 10)] + COMMON_TCP_OPTIONS    # Equivalent in hex (03030A0102040109080AFFFFFFFF000000000402)
        return (
            IP(dst=self._target_ip, flags='DF') / TCP(dport=self._open_port,   flags='',     window=128,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=self._target_ip)       /       TCP(dport=self._open_port,   flags='SFUP', window=256,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=self._target_ip, flags='DF') / TCP(dport=self._open_port,   flags='A',    window=1024,  options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=self._target_ip)       /       TCP(dport=self._closed_port, flags='S',    window=31337, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=self._target_ip, flags='DF') / TCP(dport=self._closed_port, flags='A',    window=32768, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=self._target_ip)       /       TCP(dport=self._closed_port, flags='FPU',  window=65535, options=[('WScale', 15)] + COMMON_TCP_OPTIONS)
        )


    # UDP (U1) -----------------------------------------------------------------------------------------------
    def _get_udp_packet(self) -> Packet:
        packet    = Network._create_udp_ip_packet(self._target_ip, self._closed_port)
        packet.id = 0x1042
        packet    = packet / Raw(load=b'C' * 300)
        return packet


    # RESPONSE TESTS =========================================================================================


    def _process_data(self) -> None:
        self._collect_isns_with_time()
        if len(self._isns) < 2:
            print("Insufficient responses to process.")
            return None
        self._calculate_diff1()
        self._calculate_gcd()
        self._calculate_sequence_rates()
        self._calculate_isr()


    def _collect_isns_with_time(self) -> None:
        start_time = perf_counter()
        for i, packet in enumerate(self._get_sequence_generation_packets()):
            threading.Thread(target=self._send_packet, args=(packet,))
            expected_time = start_time + (i * 0.5)
            time_to_wait  = expected_time - perf_counter()
            if time_to_wait > 0:
                sleep(time_to_wait)


    def _send_packet(self, packet:Packet) -> None:
        initial_time = perf_counter()
        response     = Network._send_a_single_layer3_packet(packet)
        final_time   = perf_counter()
        self._collect_isns_and_time(response, final_time - initial_time)


    def _collect_isns_and_time(self, response:Packet, response_time:float) -> None:
        with self._lock:
            if response and TCP in response:
                self._isns.append(response[TCP].seq)
                self._times.append(response_time)


    def _calculate_diff1(self, isns:list) -> None:
        for i in range(len(isns) - 1):
            diff         = abs(isns[i + 1] - isns[i])
            wrapped_diff = self._WRAP_LIMIT - diff
            self._diff1.append(min(diff, wrapped_diff))


    def _calculate_gcd(self) -> None:
        self._gdc = reduce(gcd, self._diff1)


    def _calculate_sequence_rates(self) -> None:
        for i in range(len(self._diff1)):
            time_diff = self._times[i + 1] - self._times[i]
            if time_diff > 0:
                self._seq_rates.append(self._diff1[i] / time_diff)


    def _calculate_isr(self) -> None:
        if not self._seq_rates: return 0
        avg_rate = sum(self._seq_rates) / len(self._seq_rates)
        if avg_rate < 1: return 0
        self._isr = round(8 * log2(avg_rate))
