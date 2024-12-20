# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all import ICMP, IP, TCP, UDP, Raw, Packet
from math      import gcd, log2, sqrt
from functools import reduce
from time      import time
from network   import Network
from auxiliary import Argument_Parser_Manager, Color


class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip   = None
        self._open_port   = None
        self._closed_port = None
        self._WRAP_LIMIT  = 4294967296    # 4.294.967.296 = 2 ** 32
        self._diff1       = None


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
    @staticmethod
    def _get_sequence_generation_packets(target_ip:str, open_port:int) -> Packet:
        return (
            IP(dst=target_ip) / TCP(dport=open_port, window=1,   options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b''),]),
            IP(dst=target_ip) / TCP(dport=open_port, window=63,  options=[('MSS', 1400),  ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=16,  options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=512, options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))])
        )


    # ICMP echo (IE) -----------------------------------------------------------------------------------------
    @staticmethod
    def _get_icmp_echo_packets(target_ip:str) -> Packet:
        return (
            IP(dst=target_ip, tos=0, flags='DF') / ICMP(type=8, code=9, id=12345, seq=295) / Raw(load=b'\x00' * 120),
            IP(dst=target_ip, tos=4)       /       ICMP(type=8, code=0, id=12346, seq=296) / Raw(load=b'\x00' * 150)
            )


    # TCP explicit congestion notification (ECN) -------------------------------------------------------------
    @staticmethod
    def _get_ecn_syn_packet(target_ip:str, target_port:str) -> Packet:
        TCP_OPTIONS        = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SACKOK', b''), ('NOP', None), ('NOP', None)]
        packet             = IP(dst=target_ip) / TCP(dport=target_port, flags="S", window=3, options=TCP_OPTIONS)
        packet[TCP].flags |= 0x18    # 0x18 = CWR (0b00010000) + ECE (0b00001000)
        return packet


    # TCP (T2–T7) --------------------------------------------------------------------------------------------
    @staticmethod
    def _get_t2_through_t7_tcp_packets(target_ip:str, open_port:int, closed_port:int) -> Packet:
        COMMON_TCP_OPTIONS        = [('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')]
        COMMOM_WSCALE_AND_OPTIONS = [('WScale', 10)] + COMMON_TCP_OPTIONS    # Equivalent in hex (03030A0102040109080AFFFFFFFF000000000402)
        return (
            IP(dst=target_ip, flags='DF') / TCP(dport=open_port,   flags='',     window=128,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=open_port,   flags='SFUP', window=256,   options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip, flags='DF') / TCP(dport=open_port,   flags='A',    window=1024,  options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=closed_port, flags='S',    window=31337, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip, flags='DF') / TCP(dport=closed_port, flags='A',    window=32768, options=COMMOM_WSCALE_AND_OPTIONS),
            IP(dst=target_ip)       /       TCP(dport=closed_port, flags='FPU',  window=65535, options=[('WScale', 15)] + COMMON_TCP_OPTIONS)
        )


    # UDP (U1) -----------------------------------------------------------------------------------------------
    @staticmethod
    def _get_udp_packet(target_ip:str, closed_port:int) -> Packet:
        packet    = Network._create_udp_ip_packet(target_ip, closed_port)
        packet.id = 0x1042
        packet    = packet / Raw(load=b'C' * 300)
        return packet


    # RESPONSE TESTS =========================================================================================

    # TCP ISN greatest common divisor (GCD) ------------------------------------------------------------------
    def _tcp_isn_gcd(self) -> None:
        isns = self._collect_isns()
        if len(isns) < 2:
            print("Insufficient responses to calculate GCD.")
            return None
        self._diff1 = self._calculate_diff1(isns)
        gcd_value   = self._calculate_gcd(self._diff1)


    def _collect_isns(self) -> list:
        packets   = self._get_sequence_generation_packets(self._target_ip, self._open_port)
        responses = Network._send_and_receive_multiple_layer3_packets(packets, 0.5)
        return [pkt.seq for pkt in responses if TCP in pkt]


    def _calculate_diff1(self, isns:list) -> list:
        diff1      = list()
        for i in range(len(isns) - 1):
            diff         = abs(isns[i + 1] - isns[i])
            wrapped_diff = self._WRAP_LIMIT - diff
            diff1.append(min(diff, wrapped_diff))
        return diff1


    @staticmethod
    def _calculate_gcd(diff1:list) -> list:
        return reduce(gcd, diff1)


    # TCP ISN counter rate (ISR) -----------------------------------------------------------------------------
    def _tcp_isn_isr(self) -> int:
        isns, times = self._collect_isns_with_time()        
        if len(isns) < 2:
            print("Insufficient responses to calculate ISR.")
            return None
        diff1 = self._calculate_diff1(isns)
        seq_rates = self._calculate_seq_rates(diff1, times)
        isr_value = self._calculate_isr(seq_rates)
        return isr_value


    def _collect_isns_with_time(self) -> tuple[list[int], list[float]]:
        """Sends TCP SYN packets and collects ISNs and corresponding timestamps."""
        packets     = self._get_sequence_generation_packets(self._target_ip, self._open_port)
        isns        = list()
        start_times = list()
        for packet in packets:
            start_time = time.time()
            response = Network._send_and_receive_multiple_layer3_packets(packet, timeout=0.5)
            if response and TCP in response:
                isns.append(response[TCP].seq)
                start_times.append(start_time)
        return isns, start_times


    def _calculate_diff1(self, isns:list[int]) -> list[int]:
        """Calculates the differences between consecutive ISNs."""
        diff1 = []
        for i in range(len(isns) - 1):
            diff = isns[i + 1] - isns[i]
            if diff < 0: diff += self._WRAP_LIMIT
            diff1.append(diff)
        return diff1


    @staticmethod
    def _calculate_seq_rates(diff1:list[int], times:list[float]) -> list[float]:
        """Calculates sequence rates based on diff1 and timestamps."""
        seq_rates = []
        for i in range(len(diff1)):
            time_diff = times[i + 1] - times[i]
            if time_diff > 0:
                seq_rates.append(diff1[i] / time_diff)
        return seq_rates


    @staticmethod
    def _calculate_isr(seq_rates:list[float]) -> int:
        """Calculates the ISR value from sequence rates."""
        if not seq_rates: return 0
        avg_rate = sum(seq_rates) / len(seq_rates)
        if avg_rate < 1: return 0
        return round(8 * log2(avg_rate))