# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/DataSeeker
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import asyncio, random
from scapy.sendrecv import sr1
from scapy.packet   import Packet


class OS_Sending:

    def __init__(self):
        self._responses = {
            'icmp_echo':      None,
            'icmp_timestamp': None,
            'icmp_addr_mask': None,
            'icmp_info':      None,
            'udp':            None,
            'tcp_syn':        None,
            'tcp_rst':        None
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
        self._responses[key] = sr1(packet, timeout=3, verbose=0)