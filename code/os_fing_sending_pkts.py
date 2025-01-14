# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading, sched, time
from scapy.all import Packet, IP, ICMP, TCP, Raw
from network   import Packets, Sending_Methods
from os_fing_pkt_analysis import *


class OS_Fingerprint_Packets(): # ============================================================================

    @staticmethod
    def _sequence_generation_packets(target_ip:str, open_port:int) -> Packet:
        """ Sequence generation (SEQ, OPS, WIN, and T1) """
        return (
            IP(dst=target_ip) / TCP(dport=open_port, window=1,   options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b''),]),
            IP(dst=target_ip) / TCP(dport=open_port, window=63,  options=[('MSS', 1400),  ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=4,   options=[('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=16,  options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            IP(dst=target_ip) / TCP(dport=open_port, window=512, options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))])
        )


    @staticmethod
    def _icmp_echo_packets(target_ip:str) -> Packet:
        """ ICMP echo (IE) """
        return (
            IP(dst=target_ip, tos=0, flags='DF') / ICMP(type=8, code=9, id=12345, seq=295) / Raw(load=b'\x00' * 120),
            IP(dst=target_ip, tos=4)       /       ICMP(type=8, code=0, id=12346, seq=296) / Raw(load=b'\x00' * 150)
            )


    @staticmethod
    def _ecn_syn_packet(target_ip:str, open_port:int) -> Packet:
        """ TCP explicit congestion notification (ECN) """
        TCP_OPTIONS        = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SACKOK', b''), ('NOP', None), ('NOP', None)]
        packet             = IP(dst=target_ip) / TCP(dport=open_port, flags="S", window=3, options=TCP_OPTIONS)
        packet[TCP].flags |= 0x18    # 0x18 = CWR (0b00010000) + ECE (0b00001000)
        return packet


    @staticmethod
    def _t2_through_t7_tcp_packets(target_ip:str, open_port:int, closed_port:int) -> Packet:
        """ TCP (T2–T7) """
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


    @staticmethod
    def _udp_packet(target_ip:str, closed_port:int) -> Packet:
        """ UDP (U1) """
        packet    = Packets._create_udp_ip_packet(target_ip, closed_port)
        packet.id = 0x1042
        packet    = packet / Raw(load=b'C' * 300)
        return packet





class ISNs_And_Times: # ======================================================================================

    def __init__(self, packets: list[Packet]):
        self._packets = packets
        self._LOCK    = threading.Lock()
        self._threads = list()
        self._isns    = list()
        self._times   = list()


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _get_isns_and_times(self) -> tuple[list, list]:
        self._schedule_sendings()
        for thread in self._threads:
            thread.join(timeout=10)
        return (self._isns, self._times)


    def _schedule_sendings(self) -> None:
        scheduler = sched.scheduler(time.time, time.sleep)
        for i, packet in enumerate(self._packets):
            scheduler.enter(i * 0.5, 1, self._create_thread, argument=(packet,))
        scheduler.run()


    def _create_thread(self, packet:Packet) -> None:
        thread = threading.Thread(target=self._send_packet, args=(packet,))
        self._threads.append(thread)
        thread.start()


    def _send_packet(self, packet:Packet) -> None:
        initial_time = time.perf_counter()
        response     = Sending_Methods._send_a_single_layer3_packet(packet)
        final_time   = time.perf_counter()
        self._collect_isns_and_time(response, final_time - initial_time)


    def _collect_isns_and_time(self, response:Packet, response_time:float) -> None:
        with self._LOCK:
            if response and TCP in response:
                self._isns.append(response[TCP].seq)
                self._times.append(response_time)





class ICMP_Testes: # =========================================================================================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    @staticmethod
    def _icmp_responses(packets:Packets) -> Packets:
        return Sending_Methods._send_and_receive_multiple_layer3_packets(packets)
    




class ECN_Syn_Packet: # ======================================================================================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    @staticmethod
    def _send_ecn_syn_packet(packet) -> Packet:
        return Sending_Methods._send_and_receive_single_layer3_packet(packet)