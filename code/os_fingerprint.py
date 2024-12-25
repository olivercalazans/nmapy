# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading
from scapy.all import TCP, Packet
from math      import gcd, log2
from functools import reduce
from time      import perf_counter, sleep
from network   import OS_Fingerprint_Packets, Network
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

    def _get_sequence_generation_packets(self) -> Packet:
        return OS_Fingerprint_Packets._sequence_generation_packets(self._target_ip, self._open_port)


    def _get_icmp_echo_packets(self) -> Packet:
        return OS_Fingerprint_Packets._icmp_echo_packets(self._target_ip)


    def _get_ecn_syn_packet(self) -> Packet:
        return OS_Fingerprint_Packets._ecn_syn_packet(self._target_ip, self._open_port)


    def _get_t2_through_t7_tcp_packets(self) -> Packet:
        return OS_Fingerprint_Packets._t2_through_t7_tcp_packets(self._target_ip, self._open_port, self._closed_port)


    def _get_udp_packet(self) -> Packet:
        return OS_Fingerprint_Packets._udp_packet(self._target_ip, self._closed_port)


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
            threading.Thread(target=self._send_packet, args=(packet,)).start()
            expected_time = start_time + (i * 0.5)
            time_to_wait  = expected_time - perf_counter()
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
