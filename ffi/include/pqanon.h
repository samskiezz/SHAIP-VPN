/*
 * pqanon.h — C ABI for native PQ-ANON front ends.
 *
 * A native shell (iOS/macOS Network Extension, Android VpnService, Windows
 * service) owns the OS packet interface and drives the tunnel through these
 * calls. They wrap the same pqanon::client code the `pqanon` CLI runs.
 *
 * Conventions:
 *  - Every call is NULL-safe; a Rust panic never unwinds into C.
 *  - `err` may be NULL; otherwise, on failure it receives a heap-allocated
 *    message to release with pqanon_string_free().
 *  - Strings returned by this library are released with pqanon_string_free().
 *  - One thread may call pqanon_tunnel_send() while another calls
 *    pqanon_tunnel_recv() on the same tunnel.
 *
 * Link: libpqanon_ffi.a (static, e.g. iOS) or libpqanon_ffi.so / .dylib / .dll.
 */
#ifndef PQANON_H
#define PQANON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A receive buffer of this size always fits one packet. */
#define PQANON_MAX_PACKET 65535

typedef struct PqanonTunnel PqanonTunnel;

typedef struct PqanonStats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t packets_received;
    uint64_t bytes_received;
    uint64_t packets_dropped; /* datagrams that did not open: replay, tamper, foreign */
} PqanonStats;

/* Library version (static; do not free). */
const char *pqanon_version(void);

/*
 * Handshake with a pqanond server and wait until it confirms the session.
 * server:                "host:port" of the UDP listener.
 * server_*_pub_hex:      the pins printed by `pqanond --identity <f> --print-public`.
 * identity_path:         this device's identity file (created 0600 if absent).
 * device_cert_path:      certificate from enrollment, or NULL (open servers).
 * Returns NULL on failure — including a device-bound server that does not
 * admit this device (unenrolled or revoked).
 */
PqanonTunnel *pqanon_tunnel_connect(const char *server,
                                    const char *server_ml_dsa_pub_hex,
                                    const char *server_ed_pub_hex,
                                    const char *identity_path,
                                    const char *device_cert_path,
                                    uint32_t timeout_ms,
                                    char **err);

/* Send one IP packet. Returns 0, or -1 on error. */
int pqanon_tunnel_send(const PqanonTunnel *t, const uint8_t *pkt, size_t len, char **err);

/* Receive one IP packet. Returns its length, 0 on timeout, -1 on error. */
long pqanon_tunnel_recv(const PqanonTunnel *t, uint8_t *buf, size_t cap,
                        uint32_t timeout_ms, char **err);

/* Server-assigned tunnel address, host order (0x0A4D0002 = 10.77.0.2); 0 if none. */
uint32_t pqanon_tunnel_assigned_ipv4(const PqanonTunnel *t);

/* Copy the traffic counters. Returns 0, or -1 if an argument is NULL. */
int pqanon_tunnel_stats(const PqanonTunnel *t, PqanonStats *out);

/* Close and free a tunnel. NULL is a no-op. */
void pqanon_tunnel_close(PqanonTunnel *t);

/*
 * Verify a pqanon://enroll link (or bare token) against the pinned
 * enrollment-authority key, locally — for a deep-link handler's confirmation
 * prompt. Returns 0 and sets *account_out (free it), or -1.
 */
int pqanon_enroll_link_verify(const char *link, const char *authority_pub_hex,
                              char **account_out, char **err);

/*
 * Enroll this device: verify the link, prove possession of the identity key,
 * then verify and store the certificate at "<identity_path>.cert".
 * Returns the device id (hex; free it), or NULL.
 */
char *pqanon_enroll(const char *link, const char *server,
                    const char *authority_pub_hex, const char *ca_pub_hex,
                    const char *identity_path, const char *name, char **err);

/* Free a string returned by this library. NULL is a no-op. */
void pqanon_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* PQANON_H */
