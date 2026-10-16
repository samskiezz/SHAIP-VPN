#!/usr/bin/env python3
"""A tiny DNS responder for the VPN lab (scripts/e2e/vpn_lab.sh).

Answers A queries for any name under .test with ANSWER_IP, NODATA for other
types under .test, NXDOMAIN otherwise. Every query is logged as
"<source-ip> <name> <type>" so the lab can prove *who* asked: the client
directly (a DNS leak) or the VPN server's forwarder.

usage: lab_dns.py BIND_IP ANSWER_IP LOG_FILE
"""
import socket
import struct
import sys


def main():
    bind_ip, answer_ip, log_path = sys.argv[1], sys.argv[2], sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, 53))
    answer = socket.inet_aton(answer_ip)
    while True:
        q, addr = s.recvfrom(4096)
        if len(q) < 17:
            continue
        i, labels = 12, []
        while i < len(q) and q[i] != 0:
            n = q[i]
            labels.append(q[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        i += 1
        if i + 4 > len(q):
            continue
        qtype, _qclass = struct.unpack(">HH", q[i:i + 4])
        qend = i + 4
        name = ".".join(labels).lower()
        with open(log_path, "a") as f:
            f.write(f"{addr[0]} {name} {qtype}\n")
        if name.endswith(".test"):
            rcode, ans = 0, b""
            if qtype == 1:
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + answer
        else:
            rcode, ans = 3, b""
        flags = 0x8180 | rcode
        header = q[:2] + struct.pack(">HHHHH", flags, 1, 1 if ans else 0, 0, 0)
        s.sendto(header + q[12:qend] + ans, addr)


if __name__ == "__main__":
    main()
