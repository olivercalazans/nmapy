# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/NetXplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading, sys, time, random
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv    import sr1, sr, send
from scapy.packet      import Packet


class Normal_Scan:

    def __init__(self, target_ip, ports, arg_flags) -> None:
        self._target_ip:str   = target_ip
        self._ports:list|int  = ports
        self._arg_flags:dict  = arg_flags
        self._packets:list    = [self._create_tcp_syn_packet(port) for port in self._ports]
        self._delay:int|float = None
        self._lock            = threading.Lock()
        self._responses:list  = list()


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _perform_normal_methods(self) -> None:
        if   self._arg_flags['delay']:   self._sendings_with_delay()
        elif self._arg_flags['stealth']: self._responses = self._send_packets()
        else:                            self._send_tcp_handshake_packets()
        return self._responses


    # PACKETS ------------------------------------------------------------------------------------------------

    def _create_tcp_syn_packet(self, port:int) -> Packet:
        return IP(dst=self._target_ip) / TCP(dport=port, flags="S")
    
    def _create_tcp_ack_packet(self, port:int, ack:int, seq:int) -> Packet:
        return IP(dst=self._target_ip) / TCP(dport=port, flags="A", seq=ack, ack=seq + 1)
    
    def _create_tcp_fin_packet(self, port:int) -> Packet:
        return IP(dst=self._target_ip) / TCP(dport=port, flags="FA")

    def _create_udp_packet(self, port:int) -> Packet:
        return IP(dst=self._target_ip, ttl=64) / UDP(dport=port)

    
    # NORMAL SENDING -----------------------------------------------------------------------------------------

    def _send_packets(self) -> list[Packet]:
        responses, _ = sr(self._packets, inter=0.1, timeout=3, verbose=0)
        return responses

    
    def _send_tcp_handshake_packets(self) -> None:
        responses   = self._send_packets()
        ack_packets = [self._create_tcp_ack_packet(pkt[TCP].sport, pkt.seq, pkt.ack) for _, pkt in responses]
        fin_packets = [self._create_tcp_fin_packet(pkt[TCP].sport) for _, pkt in responses]
        send(ack_packets, verbose=0)
        time.sleep(1)
        send(fin_packets, verbose=0)
        self._responses = responses


    # DELAY METHODS ------------------------------------------------------------------------------------------

    def _sendings_with_delay(self) -> None:
        self._get_delay_time_list()
        threads     = []
        for index ,packet in enumerate(self._packets):
            thread = threading.Thread(target=self._async_send_packet, args=(packet,))
            threads.append(thread)
            thread.start()
            sys.stdout.write(f'\rPacket sent: {index}/{len(self._packets)} - {self._delay[index]:.2}s')
            sys.stdout.flush()
            time.sleep(self._delay[index])
        for thread in threads:
            thread.join()
        print('\n')


    def _get_delay_time_list(self) -> None:
        match self._arg_flags['delay']:
            case True: delay = [random.uniform(1, 3) for _ in range(len(self._packets))]
            case _:    delay = self._create_delay_time_list()
        self._delay = delay


    def _create_delay_time_list(self) -> list:
        values = [float(value) for value in self._arg_flags['delay'].split('-')]
        if len(values) > 1: return [random.uniform(values[0], values[1]) for _ in range(len(self._packets))]
        return [values[0] for _ in range(len(self._packets))]


    def _async_send_packet(self, packet:Packet) -> None:
        response = sr1(packet, timeout=3, verbose=0)
        with self._lock:
            self._responses.append((packet, response))
