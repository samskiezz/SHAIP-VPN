/*
 * C smoke test for pqanon.h, linked against the real library and run against a
 * live pqanond by the master battery.
 *
 * usage: smoke <server> <ml_dsa_hex> <ed_hex> <identity> <cert|-> [<link> <authority_hex>]
 *
 * Expects an echo-mode server: each packet sent must come back byte-identical.
 */
#include "pqanon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, char *err) {
    fprintf(stderr, "FFI FAIL: %s: %s\n", what, err ? err : "(no message)");
    pqanon_string_free(err);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s <server> <ml_dsa_hex> <ed_hex> <identity> <cert|-> [<link> <authority_hex>]\n", argv[0]);
        return 2;
    }
    printf("pqanon %s\n", pqanon_version());
    char *err = NULL;

    /* NULL arguments fail cleanly with a message rather than crashing. */
    if (pqanon_tunnel_connect(NULL, argv[2], argv[3], argv[4], NULL, 100, &err) != NULL || err == NULL)
        return fail("NULL server was accepted", err);
    printf("NULL server refused: %s\n", err);
    pqanon_string_free(err);
    err = NULL;

    const char *cert = strcmp(argv[5], "-") == 0 ? NULL : argv[5];
    PqanonTunnel *t = pqanon_tunnel_connect(argv[1], argv[2], argv[3], argv[4], cert, 5000, &err);
    if (!t) return fail("connect", err);
    uint32_t ip = pqanon_tunnel_assigned_ipv4(t);
    printf("connected; assigned %u.%u.%u.%u\n", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);

    static uint8_t buf[PQANON_MAX_PACKET];
    for (int i = 0; i < 3; i++) {
        uint8_t pkt[300];
        size_t len = 60 + (size_t)i * 100;
        for (size_t j = 0; j < len; j++) pkt[j] = (uint8_t)(j * 7 + (size_t)i);
        if (pqanon_tunnel_send(t, pkt, len, &err) != 0) return fail("send", err);
        long n = pqanon_tunnel_recv(t, buf, sizeof buf, 3000, &err);
        if (n < 0) return fail("recv", err);
        if (n == 0) return fail("recv timed out", NULL);
        if ((size_t)n != len || memcmp(buf, pkt, len) != 0) return fail("echo mismatch", NULL);
        printf("packet %d: %zu bytes echoed intact\n", i, len);
    }
    /* Nothing more is coming: a short recv must time out (0), not error. */
    if (pqanon_tunnel_recv(t, buf, sizeof buf, 200, &err) != 0) return fail("idle recv", err);

    PqanonStats s;
    if (pqanon_tunnel_stats(t, &s) != 0) return fail("stats", NULL);
    printf("stats: sent %llu/%llu B, received %llu/%llu B, dropped %llu\n",
           (unsigned long long)s.packets_sent, (unsigned long long)s.bytes_sent,
           (unsigned long long)s.packets_received, (unsigned long long)s.bytes_received,
           (unsigned long long)s.packets_dropped);
    if (s.packets_sent != 3 || s.packets_received != 3 || s.bytes_sent != s.bytes_received)
        return fail("stats mismatch", NULL);
    pqanon_tunnel_close(t);

    if (argc >= 8) {
        char *account = NULL;
        if (pqanon_enroll_link_verify(argv[6], argv[7], &account, &err) != 0)
            return fail("enroll link verify", err);
        printf("enrollment link verifies for account %s\n", account);
        pqanon_string_free(account);
    }

    printf("FFI OK\n");
    return 0;
}
