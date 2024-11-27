# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all import ICMP, IP, TCP, UDP, Packet
from network   import Network
from auxiliary import Argument_Parser_Manager, Color


class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip   = None    # str
        self._icmp_packet = None    # Packet
        self._tcp_packet  = None    # Packet
        self._udp_packet  = None    # Packet
        self._icmp_result = None
        self._tcp_result  = None
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
        print(f"Performing OS fingerprinting with ICMP on {self._target_ip}...")
        packet   = Network._create_icmp_ip_packet(self._target_ip)
        response = Network._send_and_receive_single_layer3_packet(packet)
        if response: self._analyze_icmp_response(response)
        else: self._icmp_result = "No ICMP response received. Host unreachable or potentially blocked by firewall."


    def _analyze_icmp_response(self, icmp_packet:Packet) -> None:
        """Analyzes an ICMP response to extract relevant packet characteristics."""
        ttl_result       = self._analyze_ttl(icmp_packet.ttl)
        icmp_type_result = self._analyse_icmp_type_and_code(icmp_packet)
        self._icmp_result = f'\t{ttl_result}\n\t{icmp_type_result}'


    @staticmethod
    def _analyze_ttl(ttl:int) -> str:
        """Identifies the operating system based on the TTL value from an ICMP response."""
        if   ttl <= 64:  ttl_result = f"Likely OS: Linux/Android (TTL={ttl})"
        elif ttl <= 128: ttl_result = f"Likely OS: Windows (TTL={ttl})"
        elif ttl > 128:  ttl_result = f"Likely OS: iOS or other system with higher TTL (TTL={ttl})"
        else:            ttl_result = f"Unknown system (TTL={ttl})"
        return ttl_result


    @staticmethod
    def _analyse_icmp_type_and_code(icmp_packet:Packet) -> str:
        """Analyzes the ICMP type and code from a given packet."""
        if icmp_packet.haslayer(ICMP):
            icmp_type = icmp_packet[ICMP].type
            icmp_code = icmp_packet[ICMP].code
            if   icmp_type == 0:  icmp_type_and_code = "Echo reply received: Target is responding to ping."
            elif icmp_type == 3:  icmp_type_and_code = f"Destination Unreachable (Code {icmp_code}): Potential firewall or routing issue."
            elif icmp_type == 11: icmp_type_and_code = "Time Exceeded: Possible routing or firewall filtering."
            else:                 icmp_type_and_code = f"ICMP Type {icmp_type} (Code {icmp_code}): Unknown response."
        else:
            icmp_type_and_code = f"No ICMP layer in response"
        return icmp_type_and_code


    # TCP ----------------------------------------------------------------------------------------------------
    def _perform_tcp_fingerprint(self) -> None:
        """Performs OS fingerprinting using TCP by sending a SYN packet to the target."""
        print(f"Performing OS fingerprinting with TCP on {self._target_ip}...")
        packet   = Network._create_tpc_ip_packet(self._target_ip, 80)
        response = Network._send_and_receive_single_layer3_packet(packet)
        if response and response.haslayer(TCP):
            self._identify_os_by_tcp(response)
        else:
            print("No TCP response received.")


    def _identify_os_by_tcp(self, response:Packet) -> None:
        """Identifies the operating system based on the TCP flags from the response."""
        if   response[TCP].flags == 18: os = "TCP response received: Likely Windows or Linux-based system."
        elif response[TCP].flags == 4:  os = "TCP reset received: Likely a filtered firewall or closed port."
        elif response[TCP].flags == 2:  os = "SYN response received: Likely a system with an open port (TCP handshake)."
        elif response[TCP].flags == 1:  os = "FIN response received: System may be closing the connection (end of session)."
        else:                           os = "Unknown TCP flag combination, further analysis required."
        self._tcp_result = f'\t{os}'


    # UDP ----------------------------------------------------------------------------------------------------
    def _perform_udp_fingerprint(self) -> None:
        """Performs OS fingerprinting using UDP by sending a packet to the target."""
        print(f"Performing OS fingerprinting with UDP on {self._target_ip}...")
        packet           = Network._create_udp_ip_packet(self._target_ip, 12345, payload='Hello')
        self._udp_packet = Network._send_and_receive_single_layer3_packet(packet)
        self._analyse_udp_response()


    def _analyse_udp_response(self) -> None:
        if self._udp_packet:
            self._analyse_udp_packet(self._udp_packet)
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
