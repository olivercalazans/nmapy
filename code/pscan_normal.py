# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading, sys, time, random
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv    import sr, sr1
from scapy.packet      import Packet


class Normal_Scan:

    def __init__(self, target_ip, ports, arg_flags) -> None:
        self._target_ip:str   = target_ip
        self._ports:list|int  = ports
        self._arg_flags:dict  = arg_flags
        self._packets:list    = [self._create_tcp_packet(port) for port in self._ports]
        self._delay:int|float = None
        self._lock            = threading.Lock()
        self._responses:list  = list()


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    def _perform_normal_methods(self) -> None:
        if self._arg_flags['delay']: 
            self._async_sending()
        else:
            self._responses, _ = sr(self._packets, inter=0.1, timeout=3, verbose=0)
        return self._responses


    # PACKETS ------------------------------------------------------------------------------------------------

    def _create_tcp_packet(self, port:int) -> Packet:
        return IP(dst=self._target_ip) / TCP(dport=port, flags="S")
    
    def _create_udp_packet(self, port:int) -> Packet:
        return IP(dst=self._target_ip, ttl=64) / UDP(dport=port)


    # DELAY METHODS ------------------------------------------------------------------------------------------
    
    def _async_sending(self) -> None:
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
