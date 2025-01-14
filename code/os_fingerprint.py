# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all import Packet
from auxiliary import Color
from os_fing_pkt_analysis import *
from os_fing_sending_pkts import *


class OS_Fingerprint:
    def __init__(self, database, data:list) -> None:
        self._parser_manager = database.parser_manager
        self._data           = data
        self._target_ip      = None
        self._open_port      = None
        self._closed_port    = None
        self._isns           = None
        self._times          = None
        self._diff1          = None
        self._gcd            = None
        self._seq_rates      = None
        self._isr            = None
        self._sp             = None
        self._ip_id          = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        """Executes the fingerprinting process on the provided data."""
        try:
            self._get_argument()
            print(f'{Color.yellow("Function still under development")}')
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except ValueError as error: print(Color.display_error(error))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self) -> str:
        """Parses and retrieves the target IP address from the provided arguments."""
        arguments       = self._parser_manager._parse("OSFingerprint", self._data)
        self._target_ip = arguments.host


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


    # SENDING PACKETS ========================================================================================

    def _get_isns_and_times(self) -> None:
        with ISNs_And_Times(self._get_sequence_generation_packets()) as ISN:
            self._isns, self._times = ISN._get_isns_and_times()

    
    def _get_icmp_responses(self) -> None:
        with ICMP_Testes(self._get_icmp_echo_packets()) as ICMP:
            ...
        
    
    def _get_ecn_syn_response(self) -> None:
        with ECN_Syn_Packet(self._get_ecn_syn_packet()) as ECN:
            ...

    # RESPONSE TESTS =========================================================================================

    def _get_diff1_and_gcd(self) -> None:
        with TCP_ISN_Greatest_Common_Divisor(self._isns) as GCD:
            self._diff1, self._gcd = GCD._calculate_diff1_and_gcd()


    def _get_seq_rates_and_isr(self) -> None:
        with TCP_ISN_Counter_Rate(self._diff1, self._times) as CR:
            self._seq_rates, self._isr = CR._calculate_seq_rates_and_isr()


    def _get_sp(self) -> None:
        with TCP_ISN_Sequence_Predictability_Index(self._seq_rates, self._gcd) as SPI:
            self._sp = SPI._calculate_sp()


    def _get_sp(self) -> None:
        with IP_ID_Sequence_Analyzer() as IPID:
            self._ip_id = IPID._analyze()