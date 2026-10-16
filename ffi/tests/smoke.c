/*
 * C smoke test for pqanon.h, linked against the real library and run against a
 * live pqanond by the master battery.
 *
 * usage: smoke <server> <ml_dsa_hex> <ed_hex> <identity> <cert|-> [<link> <authority_hex>]
 *
 * Expects an echo-mode server: each packet sent must come back byte-identical.
 * Covers the bare tunnel and the reconnecting session (status, keepalive RTT,
 * a forced reconnect, stop/free).
 */
#define _POSIX_C_SOURCE 200809L /* nanosleep under -std=c11 */
#include "pqanon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int fail(const char *what, char *err) {
    fprintf(stderr, "FFI FAIL: %s: %s\n", what, err ? err : "(no message)");
    pqanon_string_free(err);
    return 1;
}

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* Send a packet on a session and expect it back (echo server); retries cover
 * a reconnect in progress. 0 on success. */
static int session_echo(PqanonSession *s, uint8_t tag) {
    static uint8_t buf[PQANON_MAX_PACKET];
    uint8_t pkt[200];
    memset(pkt, tag, sizeof pkt);
    for (int attempt = 0; attempt < 20; attempt++) {
        if (pqanon_session_send(s, pkt, sizeof pkt) != 0) return -1;
        long n = pqanon_session_recv(s, buf, sizeof buf, 500, NULL);
        if (n == (long)sizeof pkt && memcmp(buf, pkt, sizeof pkt) == 0) return 0;
        if (n < 0) return -1;
    }
    return -1;
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

    /* The reconnecting session: what an app's network extension uses. */
    PqanonSession *ss = pqanon_session_start(argv[1], argv[2], argv[3], argv[4], cert, 5000, &err);
    if (!ss) return fail("session start", err);
    PqanonStatus st;
    if (pqanon_session_status(ss, &st) != 0 || st.state != PQANON_STATE_CONNECTED)
        return fail("session not connected", NULL);
    if (st.mtu == 0 || st.mtu > 1370) return fail("session MTU", NULL);
    char *addr = pqanon_session_server_addr(ss);
    if (!addr || strcmp(addr, argv[1]) != 0) return fail("server address", addr);
    pqanon_string_free(addr);
    if (session_echo(ss, 1) != 0) return fail("session echo", NULL);
    for (int i = 0; i < 40 && (pqanon_session_status(ss, &st), st.rtt_us == 0); i++) nap_ms(100);
    if (st.rtt_us == 0) return fail("no keepalive RTT measured", NULL);
    int zero_id = 1;
    for (int i = 0; i < 16; i++) zero_id &= st.server_identity[i] == 0;
    if (zero_id) return fail("no server identity", NULL);
    printf("session: connected, mtu %u, keepalive RTT %.2f ms, server %02x%02x%02x%02x…\n", st.mtu, st.rtt_us / 1000.0,
           st.server_identity[0], st.server_identity[1], st.server_identity[2], st.server_identity[3]);

    /* A network change: renegotiate now; packets flow on the new session. */
    if (pqanon_session_reconnect(ss) != 0) return fail("reconnect", NULL);
    for (int i = 0; i < 100 && (pqanon_session_status(ss, &st), st.reconnects < 1 || st.state != PQANON_STATE_CONNECTED); i++)
        nap_ms(100);
    if (st.reconnects != 1 || st.state != PQANON_STATE_CONNECTED) return fail("did not reconnect", pqanon_session_last_error(ss));
    if (session_echo(ss, 2) != 0) return fail("echo after reconnect", NULL);
    printf("session: reconnected (#%u), packets flow\n", st.reconnects);

    pqanon_session_stop(ss);
    if (pqanon_session_recv(ss, buf, sizeof buf, 1000, &err) != -1) return fail("recv after stop", err);
    pqanon_string_free(err);
    err = NULL;
    pqanon_session_status(ss, &st);
    if (st.state != PQANON_STATE_STOPPED) return fail("not stopped", NULL);
    printf("session: stopped; sent %llu, received %llu packets in total\n",
           (unsigned long long)st.stats.packets_sent, (unsigned long long)st.stats.packets_received);
    pqanon_session_free(ss);

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
