# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import asyncio, random
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv    import sr1
from scapy.packet      import Packet
from auxiliary         import Color, Argument_Parser_Manager


class OS_Fingerprint:
    def __init__(self, parser_manager:Argument_Parser_Manager, data:list) -> None:
        self._parser_manager = parser_manager
        self._data           = data
        self._target_ip      = None
        self._packets        = None
        self._responses      = None


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _execute(self) -> None:
        try:
            self._get_argument()
            print(f'{Color.yellow("Function still under development")}')
            #self._create_packets()
            #asyncio.run(self._get_responses())
        except SystemExit as error: print(Color.display_invalid_missing()) if not error.code == 0 else print()
        except KeyboardInterrupt:   print(Color.red("Process stopped"))
        except ValueError as error: print(Color.display_error(error))
        except Exception as error:  print(Color.display_unexpected_error(error))


    def _get_argument(self) -> str:
        arguments       = self._parser_manager._parse("OSFingerprint", self._data)
        self._target_ip = arguments.host

    
    def _create_packets(self) -> None:
        port_high = random.randint(1024, 65535)
        self._packets = (
            IP(dst=self._target_ip) / ICMP(type=8, code=0),
            IP(dst=self._target_ip) / ICMP(type=13, code=0),
            IP(dst=self._target_ip) / ICMP(type=17, code=0),
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="S"),
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="A", sport=port_high), 
            IP(dst=self._target_ip) / TCP(dport=port_high, flags="F", sport=port_high),
            IP(dst=self._target_ip) / TCP(dport=80, flags="S"),
            IP(dst=self._target_ip) / TCP(dport=80, flags="A", sport=80),
            IP(dst=self._target_ip) / TCP(dport=80, flags="F", sport=80),
            IP(dst=self._target_ip) / UDP(dport=port_high),
            IP(dst=self._target_ip) / UDP(dport=53)
        )


    async def _get_responses(self) -> None:
        with OS_Sending() as responses:
            self._responses = await responses._perform_sending(self._packets)






class OS_Sending: # ==========================================================================================

    def __init__(self):
        self._responses = {
            'icmp_echo':      None,
            'icmp_timestamp': None,
            'icmp_addr_mask': None,
            'tcp_syn1':       None,
            'tcp_ack1':       None,
            'tcp_fin1':       None,
            'tcp_syn2':       None,
            'tcp_ack2':       None,
            'tcp_fin2':       None,
            'udp1':           None,
            'udp2':           None
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    async def _perform_sending(self, packets:list[Packet]) -> dict[Packet]:
        for packet, key in zip(packets, self._responses.keys()):
            await self._get_response(packet, key)
            await asyncio.sleep(random.uniform(0.5, 2))
        return self._responses


    async def _get_response(self, packet:Packet, key:str) -> None:
        self._responses[key] = sr1(packet, timeout=5, verbose=0)