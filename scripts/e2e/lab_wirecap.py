#!/usr/bin/env python3
"""What the ISP sees: capture the VPN's packets on a router interface and
summarize them, for scripts/e2e/vpn_lab.sh.

    lab_wirecap.py IFACE CLIENT_IP SERVER_IP SERVER_PORT OUT.json

Runs until SIGTERM, then writes OUT.json with what a DPI box on that link
could measure: IP fragments, datagram sizes, handshake-sized datagrams, any
occurrence of the protocol magic, and, per direction, how often the most
common value appears at each of the first 64 byte positions (a fixed header
shows up as a position where one value dominates; random bytes give ~1/256).
"""
import json
import signal
import socket
import struct
import sys

ETH_P_ALL = 0x0003
BOOT_DATAGRAM = 1200
POSITIONS = 64


def main():
    iface, client, server, port, out = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
    cl, sv = socket.inet_aton(client), socket.inet_aton(server)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    s.settimeout(0.2)
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))

    frags = 0
    sizes = {"c2s": [], "s2c": []}
    boot = {"c2s": 0, "s2c": 0}
    magic = 0
    counts = {d: [[0] * 256 for _ in range(POSITIONS)] for d in ("c2s", "s2c")}
    data_packets = {"c2s": 0, "s2c": 0}

    while not stop:
        try:
            frame = s.recv(65535)
        except socket.timeout:
            continue
        if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        src, dst = ip[12:16], ip[16:20]
        if {src, dst} != {cl, sv}:
            continue
        flags_off = struct.unpack("!H", ip[6:8])[0]
        if flags_off & 0x2000 or flags_off & 0x1FFF:
            frags += 1
            if flags_off & 0x1FFF:
                continue  # a later fragment carries no UDP header
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        payload = ip[ihl + 8:]
        if src == cl and dport == port:
            d = "c2s"
        elif src == sv and sport == port:
            d = "s2c"
        else:
            continue
        sizes[d].append(len(payload))
        if b"PQAN" in payload:
            magic += 1
        if len(payload) == BOOT_DATAGRAM:
            boot[d] += 1
            continue
        data_packets[d] += 1
        for i, b in enumerate(payload[:POSITIONS]):
            counts[d][i][b] += 1

    def max_share(d):
        n = data_packets[d]
        if not n:
            return None
        return max(max(c) for c in counts[d]) / n

    summary = {
        "ip_fragments": frags,
        "datagrams": {d: len(v) for d, v in sizes.items()},
        "max_datagram": max((max(v) for v in sizes.values() if v), default=0),
        "boot_datagrams": boot,
        "data_packets": data_packets,
        "magic_hits": magic,
        "max_position_share": {d: max_share(d) for d in ("c2s", "s2c")},
    }
    with open(out, "w") as f:
        json.dump(summary, f)


if __name__ == "__main__":
    main()
