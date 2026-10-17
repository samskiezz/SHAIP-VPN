/*
 * pqanon.h — C ABI for native SHAIP VPN front ends.
 *
 * A native shell (iOS/macOS Network Extension, Android VpnService, Windows
 * service) owns the OS packet interface and drives the tunnel through these
 * calls. They wrap the same code the `pqanon` CLI runs:
 *
 *  - pqanon_session_*: the link an app should use. It keeps itself up —
 *    keepalive (with a measured RTT), dead-peer detection, reconnection with
 *    backoff, rekeying by fresh handshake — exactly like `pqanon run`.
 *  - pqanon_tunnel_*: one bare session, no keepalive or reconnect (probes,
 *    tests).
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
 * Returns the device id (hex; free it), or NULL. `name` is reduced to a
 * platform label (iPhone, iPad, Android, Windows, Linux, Mac, or "device")
 * before anything is sent: pass the platform, never the user's device name.
 */
char *pqanon_enroll(const char *link, const char *server,
                    const char *authority_pub_hex, const char *ca_pub_hex,
                    const char *identity_path, const char *name, char **err);

/* ---- Reconnecting session --------------------------------------------- */

typedef struct PqanonSession PqanonSession;

#define PQANON_STATE_CONNECTED    0  /* a confirmed session carries traffic */
#define PQANON_STATE_RECONNECTING 1  /* negotiating a new session; packets are dropped meanwhile */
#define PQANON_STATE_STOPPED      2

typedef struct PqanonStatus {
    int32_t state;              /* PQANON_STATE_* */
    uint32_t assigned_ipv4;     /* tunnel address, host order; 0 if none */
    uint8_t prefix_len;
    uint32_t gateway_ipv4;      /* the server's tunnel address; 0 if none */
    uint32_t dns_ipv4;          /* resolver to use (reached through the tunnel); 0: none pushed */
    uint16_t mtu;               /* MTU for the tunnel interface */
    uint32_t rtt_us;            /* smoothed keepalive RTT; 0 until measured */
    uint64_t up_since_unix_ms;  /* when the link came up (rekeys keep it); 0 while down */
    uint32_t reconnects;        /* sessions re-established after a failure */
    uint32_t rekeys;            /* sessions replaced by a scheduled rekey */
    PqanonStats stats;          /* totals across every session of this link */
    uint64_t dropped_offline;   /* outbound packets dropped while no session was up */
    uint8_t server_identity[16];/* the server's identity_id (as `pqanond --print-public` shows), proven by the handshake */
} PqanonStatus;

/*
 * Connect, wait for the server to confirm the first session, then keep the
 * link up in the background. Arguments as for pqanon_tunnel_connect. NULL on
 * failure of the first connection (wrong pins, not admitted, unreachable).
 */
PqanonSession *pqanon_session_start(const char *server,
                                    const char *server_ml_dsa_pub_hex,
                                    const char *server_ed_pub_hex,
                                    const char *identity_path,
                                    const char *device_cert_path,
                                    uint32_t timeout_ms,
                                    char **err);

/* Send one IP packet; dropped (and counted) while reconnecting. 0, or -1 for bad arguments. */
int pqanon_session_send(const PqanonSession *s, const uint8_t *pkt, size_t len);

/* Receive one IP packet across reconnects: its length, 0 on timeout, -1 once stopped. */
long pqanon_session_recv(const PqanonSession *s, uint8_t *buf, size_t cap,
                         uint32_t timeout_ms, char **err);

/* Copy a status snapshot. 0, or -1 if an argument is NULL. */
int pqanon_session_status(const PqanonSession *s, PqanonStatus *out);

/* The server's UDP address as resolved and used, e.g. "203.0.113.7:443" (free it). */
char *pqanon_session_server_addr(const PqanonSession *s);

/* Why the last session ended or the last attempt failed (free it), or NULL. */
char *pqanon_session_last_error(const PqanonSession *s);

/* Renegotiate now, e.g. after the device changed networks. 0, or -1 if s is NULL. */
int pqanon_session_reconnect(const PqanonSession *s);

/*
 * Close the session (telling the server) and stop reconnecting; blocked and
 * later pqanon_session_recv calls return -1. The session stays allocated.
 */
void pqanon_session_stop(const PqanonSession *s);

/* Free a session (stopping it first if needed). No other thread may be inside
 * a pqanon_session_* call on it. NULL is a no-op. */
void pqanon_session_free(PqanonSession *s);

/* Free a string returned by this library. NULL is a no-op. */
void pqanon_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* PQANON_H */
