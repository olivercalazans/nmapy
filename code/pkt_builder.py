# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, struct, random
from display import RawPacket


# PACKET BUILDERS --------------------------------------------------------------------------------------------

def create_tcp_packet(dst_ip:str, port:int, src_ip:str) -> RawPacket:
    ip_header  = IP(dst_ip, src_ip, socket.IPPROTO_TCP)
    tcp_header = TCP(dst_ip, port, src_ip)
    return RawPacket(ip_header + tcp_header)



# LAYERS -----------------------------------------------------------------------------------------------------

def IP(dst_ip:str, src_ip:str, protocol) -> bytes:
    return struct.pack('!BBHHHBBH4s4s',
                       (4 << 4) + 5, #...................: IP version and IHL (Internet Header Length)
                       0, #..............................: TOS (Type of Service)
                       40, #.............................: Total length
                       random.randint(10000, 65535), #...: IP ID
                       0, #..............................: Flags and Fragment offset
                       64, #.............................: TLL (Time to Live)
                       protocol, #.......................: Protocol
                       0, #..............................: Checksum (Will be populated by the kernel)
                       socket.inet_aton(src_ip), #.......: Source IP
                       socket.inet_aton(dst_ip) #........: Destiny IP
                       )



def TCP(dst_ip:str, dst_port:int, src_ip:str, seq=0, ack_seq=0, syn_flag=True) -> bytes:
    src_port   = random.randint(10000, 65535)
    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, #.............: Source port
                             dst_port, #.............: Destiny port
                             seq, #..................: Sequence
                             ack_seq, #..............: Acknowledge
                             (5 << 4), #.............: Data offset = 5 words (20 bytes), no options
                             (syn_flag << 1), #......: Flags
                             socket.htons(5840), #...: Window size
                             0, #....................: Checksum (will be calculated)
                             0 #.....................: Urgent pointer
                             )
    pseudo_hdr   = pseudo_header(src_ip, dst_ip, len(tcp_header))
    tcp_checksum = checksum(pseudo_hdr + tcp_header)

    return struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq, (5 << 4),
                       (syn_flag << 1), socket.htons(5840), tcp_checksum, 0)



def pseudo_header(dst_ip:str, src_ip:str, tcp_length:int) -> bytes:
    return struct.pack('!4s4sBBH',
                       socket.inet_aton(src_ip), #...: Source IP
                       socket.inet_aton(dst_ip), #...: Destiny IP
                       0, #..........................: Reserved
                       socket.IPPROTO_TCP, #.........: Protocol
                       tcp_length #..................: TCP header length
                       )



def checksum(msg) -> int:
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff
