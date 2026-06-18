#!/usr/bin/env python3
"""Generate a comprehensive test pcap for epan tool verification."""
import struct
import time
import os

OUT = os.path.join(os.path.dirname(__file__), "testdata", "test.pcap")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1
ETH_P_IP = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17

def ip_checksum(header):
    if len(header) % 2 != 0:
        header += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(header)//2), header))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def tcp_checksum(src_ip, dst_ip, proto, payload):
    pseudo = src_ip + dst_ip + struct.pack('!BBH', 0, proto, len(payload))
    data = pseudo + payload
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def make_ip(src_ip, dst_ip, proto, payload, ttl=64):
    ihl = 5
    ver = 4
    total_len = (ihl * 4) + len(payload)
    hdr = struct.pack('!BBHHHBBH', (ver << 4) | ihl, 0, total_len, 0, 0x4000, ttl, proto, 0)
    hdr = hdr[:10] + struct.pack('!H', ip_checksum(hdr)) + src_ip + dst_ip
    return hdr + payload

def make_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, window=65535):
    data_offset = 5
    hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, (data_offset << 4), flags, window, 0, 0)
    cksum = tcp_checksum(src_ip, dst_ip, IPPROTO_TCP, hdr + payload)
    return struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, (data_offset << 4), flags, window, cksum, 0) + payload

def make_udp(src_ip, dst_ip, src_port, dst_port, payload):
    return struct.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0) + payload

def make_eth(src_mac, dst_mac, eth_type):
    return dst_mac + src_mac + struct.pack('!H', eth_type)

def make_pkt(ts, payload):
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    pkt_hdr = struct.pack('!IIII', ts_sec, ts_usec, len(payload), len(payload))
    return pkt_hdr + payload

IP_A = struct.pack('!4B', 10, 0, 0, 1)
IP_B = struct.pack('!4B', 10, 0, 0, 2)
IP_C = struct.pack('!4B', 10, 0, 0, 3)
IP_D = struct.pack('!4B', 192, 168, 1, 100)
IP_E = struct.pack('!4B', 192, 168, 1, 200)
MAC_A = b'\x00\x11\x22\x33\x44\x01'
MAC_B = b'\x00\x11\x22\x33\x44\x02'
MAC_C = b'\x00\x11\x22\x33\x44\x03'

frames = []
ts = 0.0

def add_frame(ts, src_mac, dst_mac, src_ip, dst_ip, proto, transport):
    eth = make_eth(src_mac, dst_mac, ETH_P_IP)
    ip = make_ip(src_ip, dst_ip, proto, transport)
    frames.append(make_pkt(ts, eth + ip))

# === Stream 0: TCP HTTP (A->B) ===
seq_a, seq_b = 1000, 5000
# SYN
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 12345, 80, seq_a, 0, 0x02, b''))
ts += 0.001; seq_a += 1
# SYN-ACK
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 80, 12345, seq_b, seq_a, 0x12, b''))
ts += 0.001; seq_b += 1
# ACK
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 12345, 80, seq_a, seq_b, 0x10, b''))
ts += 0.001
# HTTP GET
http_get = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 12345, 80, seq_a, seq_b, 0x18, http_get))
ts += 0.001; seq_a += len(http_get)
# ACK
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 80, 12345, seq_b, seq_a, 0x10, b''))
ts += 0.001
# HTTP 200
http_resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello!</body></html>'
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 80, 12345, seq_b, seq_a, 0x18, http_resp))
ts += 0.001; seq_b += len(http_resp)
# FIN/ACK exchange
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 12345, 80, seq_a, seq_b, 0x11, b''))
ts += 0.001; seq_a += 1
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 80, 12345, seq_b, seq_a, 0x11, b''))
ts += 0.001; seq_b += 1
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 12345, 80, seq_a, seq_b, 0x10, b''))
ts += 0.002

# === Stream 1: TCP TLS (C->D) ===
seq_c, seq_d = 3000, 7000
add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, 0, 0x02, b''))
ts += 0.001; seq_c += 1
add_frame(ts, MAC_A, MAC_C, IP_D, IP_C, IPPROTO_TCP, make_tcp(IP_D, IP_C, 443, 54321, seq_d, seq_c, 0x12, b''))
ts += 0.001; seq_d += 1
add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, seq_d, 0x10, b''))
ts += 0.001
add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, seq_d, 0x18, b'\x16\x03\x01\x01\x00' + b'\x00' * 32))
ts += 0.001; seq_c += 37
add_frame(ts, MAC_A, MAC_C, IP_D, IP_C, IPPROTO_TCP, make_tcp(IP_D, IP_C, 443, 54321, seq_d, seq_c, 0x18, b'\x16\x03\x03\x00\x51' + b'\x00' * 10))
ts += 0.001; seq_d += 15
for i in range(3):
    data = b'DATA_%02d' % i + b'\x00' * 20
    add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, seq_d, 0x18, data))
    ts += 0.001; seq_c += len(data)
add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, seq_d, 0x11, b''))
ts += 0.001; seq_c += 1
add_frame(ts, MAC_A, MAC_C, IP_D, IP_C, IPPROTO_TCP, make_tcp(IP_D, IP_C, 443, 54321, seq_d, seq_c, 0x11, b''))
ts += 0.001; seq_d += 1
add_frame(ts, MAC_C, MAC_A, IP_C, IP_D, IPPROTO_TCP, make_tcp(IP_C, IP_D, 54321, 443, seq_c, seq_d, 0x10, b''))
ts += 0.002

# === UDP DNS queries ===
for i in range(5):
    dns_q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_UDP, make_udp(IP_A, IP_B, 53000 + i, 53, dns_q))
    ts += 0.001
    dns_r = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22'
    add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_UDP, make_udp(IP_B, IP_A, 53, 53000 + i, dns_r))
    ts += 0.001

# More UDP to different hosts
for i in range(5):
    add_frame(ts, MAC_C, MAC_A, IP_C, IP_E, IPPROTO_UDP, make_udp(IP_C, IP_E, 8080 + i, 161, b'\x30\x20\x02\x01\x01\x04\x04public'))
    ts += 0.001

# === Stream 2: TCP bulk data (for pagination) ===
seq_a2, seq_b2 = 20000, 30000
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 23456, 8080, seq_a2, 0, 0x02, b''))
ts += 0.001; seq_a2 += 1
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 8080, 23456, seq_b2, seq_a2, 0x12, b''))
ts += 0.001; seq_b2 += 1
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 23456, 8080, seq_a2, seq_b2, 0x10, b''))
ts += 0.001
# 30 bulk data frames
for i in range(30):
    data = b'BULK_%03d' % i + b' ' * 100
    add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 23456, 8080, seq_a2, seq_b2, 0x18, data))
    ts += 0.001; seq_a2 += len(data)
# FIN
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 23456, 8080, seq_a2, seq_b2, 0x11, b''))
ts += 0.001; seq_a2 += 1
add_frame(ts, MAC_B, MAC_A, IP_B, IP_A, IPPROTO_TCP, make_tcp(IP_B, IP_A, 8080, 23456, seq_b2, seq_a2, 0x11, b''))
ts += 0.001; seq_b2 += 1
add_frame(ts, MAC_A, MAC_B, IP_A, IP_B, IPPROTO_TCP, make_tcp(IP_A, IP_B, 23456, 8080, seq_a2, seq_b2, 0x10, b''))

# Write pcap
pcap_hdr = struct.pack('!IHHiIII', PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, 65535, LINKTYPE_ETHERNET)

with open(OUT, 'wb') as f:
    f.write(pcap_hdr)
    for pkt in frames:
        f.write(pkt)

print(f"Generated {len(frames)} frames -> {OUT}")
print(f"File size: {os.path.getsize(OUT)} bytes")