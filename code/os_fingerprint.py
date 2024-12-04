# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all import ICMP, IP, TCP, UDP, Raw, Packet
from network   import Network
from auxiliary import Argument_Parser_Manager, Color


class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip   = None    # str
        self._icmp_packet = None    # Packet
        self._tcp_packet  = None    # Packet
        self._udp_packet  = None    # Packet
        self._icmp_result = list()
        self._tcp_result  = list()
        self._udp_result  = dict()


    def _execute(self, database, data:list) -> None:
        """Executes the fingerprinting process on the provided data."""
        try:
            self._get_argument(database.parser_manager, data)
            self._perform_icmp_fingerprint()
            self._perform_tcp_fingerprint()
            self._perform_udp_fingerprint()
            self._display_result()
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self, parser_manager:Argument_Parser_Manager, argument:list) -> str:
        """Parses and retrieves the target IP address from the provided arguments."""
        arguments = parser_manager._parse("OSFingerprint", argument)
        self._target_ip = arguments.target


    # ICMP ---------------------------------------------------------------------------------------------------
    def _perform_icmp_fingerprint(self) -> None:
        """Performs OS fingerprinting using ICMP by sending an ICMP packet to the target."""
        print(f'Performing OS fingerprinting with ICMP on {self._target_ip}...')
        packets   = [self._create_first_icmp_packet(self._target_ip), self._create_second_icmp_packet(self._target_ip)]
        responses = [Network._send_and_receive_single_layer3_packet(pkt) for pkt in packets]
        if responses: self._analyze_icmp_response(responses)
        else: self._icmp_result.append('No ICMP response received. Host unreachable or potentially blocked by firewall.')


    @staticmethod
    def _create_first_icmp_packet(target_ip:str) -> Packet:
        packet_1 = Network._create_icmp_ip_packet(target_ip)
        packet_1[IP].flags  = 'DF'
        packet_1[IP].tos    = 0
        packet_1[ICMP].type = 8
        packet_1[ICMP].code = 9
        packet_1[ICMP].id   = 12345
        packet_1[ICMP].seq  = 295
        return packet_1 / Raw(load=b'\x00' * 120)


    @staticmethod
    def _create_second_icmp_packet(target_ip:str) -> Packet:
        packet_2 = Network._create_icmp_ip_packet(target_ip)
        packet_2[IP].tos    = 4
        packet_2[ICMP].type = 8
        packet_2[ICMP].code = 0
        packet_2[ICMP].id   = 12346
        packet_2[ICMP].seq  = 296
        return packet_2 / b'\x00' * 150


    def _analyze_icmp_response(self, icmp_packets:Packet) -> None:
        """Analyzes an ICMP response to extract relevant packet characteristics."""
        for packet in icmp_packets:
            ttl_result        = self._analyze_ttl(packet.ttl)
            icmp_type_result  = self._analyse_icmp_type_and_code(packet)
            self._icmp_result.append(f'\t{ttl_result}\n\t{icmp_type_result}')


    @staticmethod
    def _analyze_ttl(ttl:int) -> str:
        """Identifies the operating system based on the TTL value from an ICMP response."""
        if   ttl <= 64:  ttl_result = f'Likely OS: Linux/Android (TTL={ttl})'
        elif ttl <= 128: ttl_result = f'Likely OS: Windows (TTL={ttl})'
        elif ttl > 128:  ttl_result = f'Likely OS: iOS or other system with higher TTL (TTL={ttl})'
        else:            ttl_result = f'Unknown system (TTL={ttl})'
        return ttl_result


    @staticmethod
    def _analyse_icmp_type_and_code(icmp_packet:Packet) -> str:
        """Analyzes the ICMP type and code from a given packet."""
        if icmp_packet.haslayer(ICMP):
            icmp_type = icmp_packet[ICMP].type
            icmp_code = icmp_packet[ICMP].code
            if   icmp_type == 0:  icmp_type_and_code = 'Echo reply received: Target is responding to ping.'
            elif icmp_type == 3:  icmp_type_and_code = f'Destination Unreachable (Code {icmp_code}): Potential firewall or routing issue.'
            elif icmp_type == 11: icmp_type_and_code = 'Time Exceeded: Possible routing or firewall filtering.'
            else:                 icmp_type_and_code = f'ICMP Type {icmp_type} (Code {icmp_code}): Unknown response.'
        else:
            icmp_type_and_code = f'No ICMP layer in response'
        return icmp_type_and_code


    # TCP ----------------------------------------------------------------------------------------------------
    def _perform_tcp_fingerprint(self) -> None:
        """Performs OS fingerprinting using TCP by sending a SYN packet to the target."""
        print(f'Performing OS fingerprinting with TCP on {self._target_ip}...')
        packets   = self._get_sequence_packets(self._target_ip) + self._get_test_packets(self._target_ip)
        responses = Network._send_and_receive_multiple_layer3_packets(packets)
        answers   = [i.answer for i in responses] 
        self._process_tcp_responses(answers)


    @staticmethod
    def _get_sequence_packets(target_ip:str) -> list:
        PACKET = Network._create_tpc_ip_packet(target_ip, 12345)
        return [
            PACKET / TCP(window=1,   options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b''),]),
            PACKET / TCP(window=63,  options=[('MSS', 1400),  ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
            PACKET / TCP(window=4,   options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]),
            PACKET / TCP(window=4,   options=[('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            PACKET / TCP(window=16,  options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
            PACKET / TCP(window=512, options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))])
            ]


    @staticmethod
    def _get_test_packets(target_ip:str) -> Packet:
        TCP_OPTIONS  = [('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')]
        return [
            IP(dst=target_ip, flags='DF') / TCP(window=128,   flags='S', options=[('WScale', 10)] + TCP_OPTIONS),
            IP(dst=target_ip)       /       TCP(window=256,   flags='A', options=[('WScale', 10)] + TCP_OPTIONS),
            IP(dst=target_ip, flags='DF') / TCP(window=1024,  flags='A', options=[('WScale', 10)] + TCP_OPTIONS),
            IP(dst=target_ip)       /       TCP(window=31337, flags='S', options=[('WScale', 10)] + TCP_OPTIONS, dport=12345),
            IP(dst=target_ip, flags='DF') / TCP(window=32768, flags='A', options=[('WScale', 10)] + TCP_OPTIONS, dport=12345),
            IP(dst=target_ip)       /       TCP(window=65535, flags='S', options=[('WScale', 15)] + TCP_OPTIONS, dport=12345)
        ]


    def _process_tcp_responses(self, responses:Packet) -> None:
        for packet in responses:
            if packet and packet.haslayer(TCP):
                self._identify_os_by_tcp(packet)
            else:
                self._tcp_result.append(f'No TCP response received. >> {packet}')


    def _identify_os_by_tcp(self, response:Packet) -> None:
        """Identifies the operating system based on the TCP flags from the response."""
        if   response[TCP].flags == 18: os = 'TCP response received: Likely Windows or Linux-based system.'
        elif response[TCP].flags == 4:  os = 'TCP reset received: Likely a filtered firewall or closed port.'
        elif response[TCP].flags == 2:  os = 'SYN response received: Likely a system with an open port (TCP handshake).'
        elif response[TCP].flags == 1:  os = 'FIN response received: System may be closing the connection (end of session).'
        else:                           os = 'Unknown TCP flag combination, further analysis required.'
        self._tcp_result.append(f'\t{os}\n')


    # UDP ----------------------------------------------------------------------------------------------------
    def _perform_udp_fingerprint(self) -> None:
        """Performs OS fingerprinting using UDP by sending a packet to the target."""
        print(f'Performing OS fingerprinting with UDP on {self._target_ip}...')
        packet           = self._prepare_udp_packet()
        self._udp_packet = Network._send_and_receive_single_layer3_packet(packet)
        self._analyse_udp_response()


    def _prepare_udp_packet(self) -> Packet:
        packet    = Network._create_udp_ip_packet(self._target_ip, 12345)
        packet.id = 0x1042
        packet    = packet / Raw(load=b'C' * 300)
        return packet


    def _analyse_udp_response(self) -> None:
        if self._udp_packet:
            self._analyse_udp_packet()
        else:
            self._udp_result.update({'error': 'No UDP response'})


    def _analyse_udp_packet(self) -> str:
        ttl                = self._udp_packet[IP].ttl
        packet_len         = len(self._udp_packet)
        fragmentation_flag = self._udp_packet[IP].flags
        self._udp_result.update({'ttl': ttl, 'len': packet_len, 'flags': fragmentation_flag})
        if    self._udp_packet.haslayer(UDP):  self._analyse_udp_layer()
        elif  self._udp_packet.haslayer(ICMP): self._analyse_icmp_layer()
        else: self._udp_result.update({'error':'Unknown protocol'})


    def _analyse_udp_layer(self) -> None:
        source_port      = self._udp_packet[UDP].sport
        destination_port = self._udp_packet[UDP].dport
        checksum         = self._udp_packet[UDP].chksum
        payload          = self._udp_packet[UDP].payload
        self._udp_result.update({'sport': source_port, 'dport': destination_port, 'cksum': checksum, 'payload': payload})


    def _analyse_icmp_layer(self) -> None:
        type        = self._udp_packet[ICMP].type
        code        = self._udp_packet[ICMP].code
        description = self._udp_packet[ICMP].summary
        self._udp_result.update({'type': type, 'code': code, 'desc': description})


    # RESULTS ------------------------------------------------------------------------------------------------
    def _display_result(self) -> None:
        """Displays the results of the OS fingerprinting performed using ICMP, TCP, and UDP."""
        print(f'{Color.green("ICMP result")}:\n{self._icmp_result}')
        print(f'{Color.green("TCP result")}:\n{self._tcp_result}')
        print(f'{Color.green("UDP result")}:\n{self._udp_result}')
