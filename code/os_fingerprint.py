# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from scapy.all import TCP, UDP, packet
from network   import Network
from auxiliary import Argument_Parser_Manager, Color


class OS_Fingerprint:
    def __init__(self) -> None:
        self._target_ip   = None
        self._icmp_result = None
        self._tcp_result  = None
        self._udp_result  = None


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


    # ICMP --------------------------------------------------------------------------------------------------------------------
    def _perform_icmp_fingerprint(self) -> None:
        """Performs OS fingerprinting using ICMP by sending an ICMP packet to the target."""
        print(f"Performing OS fingerprinting with ICMP on {self._target_ip}...")
        packet   = Network._create_icmp_ip_packet(self._target_ip)
        response = Network._send_and_receive_single_layer3_packet(packet)
        if response: self._identify_os_by_icmp(response.ttl)
        else: self._icmp_result = "No ICMP response received from the target."


    def _identify_os_by_icmp(self, ttl:int) -> None:
        """Identifies the operating system based on the TTL value from an ICMP response."""
        if   ttl <= 64:  os = "Probably Linux/Android"
        elif ttl <= 128: os = "Probably Windows"
        elif ttl > 128:  os = "Probably iOS or another system with a higher TTL"
        else:            os = "Unknown operating system"
        self._icmp_result = os


    # TCP ---------------------------------------------------------------------------------------------------------------------
    def _perform_tcp_fingerprint(self) -> None:
        """Performs OS fingerprinting using TCP by sending a SYN packet to the target."""
        print(f"Performing OS fingerprinting with TCP on {self._target_ip}...")
        packet   = Network._create_tpc_ip_packet(self._target_ip, 80)
        response = Network._send_and_receive_single_layer3_packet(packet)
        if response and response.haslayer(TCP):
            self._identify_os_by_tcp(response)
        else:
            print("No TCP response received.")


    def _identify_os_by_tcp(self, response:packet) -> None:
        """Identifies the operating system based on the TCP flags from the response."""
        if   response[TCP].flags == 18: os = "TCP response received: Likely Windows or Linux-based system."
        elif response[TCP].flags == 4:  os = "TCP reset received: Likely a filtered firewall or closed port."
        elif response[TCP].flags == 2:  os = "SYN response received: Likely a system with an open port (TCP handshake)."
        elif response[TCP].flags == 1:  os = "FIN response received: System may be closing the connection (end of session)."
        else:                           os = "Unknown TCP flag combination, further analysis required."
        self._tcp_result = os


    # UDP ---------------------------------------------------------------------------------------------------------------------
    def _perform_udp_fingerprint(self) -> None:
        """Performs OS fingerprinting using UDP by sending a packet to the target."""
        print(f"Performing OS fingerprinting with UDP on {self._target_ip}...")
        packet   = Network._create_udp_ip_packet(self._target_ip, 53)
        response = Network._send_and_receive_single_layer3_packet(packet)
        if response and response.haslayer(UDP):
            self._udp_result = "UDP response received: Likely Linux or Unix-based system."
        else:
            self._udp_result = "No UDP response received."


    def _display_result(self) -> None:
        """Displays the results of the OS fingerprinting performed using ICMP, TCP, and UDP."""
        print(f'ICMP result...: {self._icmp_result}')
        print(f'TCP result....: {self._tcp_result}')
        print(f'UDP result....: {self._udp_result}')
