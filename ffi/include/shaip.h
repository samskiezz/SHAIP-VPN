/*
 * shaip.h — C ABI for native SHAIP VPN front ends.
 *
 * A native shell (iOS/macOS Network Extension, Android VpnService, Windows
 * service) owns the OS packet interface and drives the tunnel through these
 * calls. They wrap the same code the `shaip` CLI runs:
 *
 *  - shaip_session_*: the link an app should use. It keeps itself up —
 *    keepalive (with a measured RTT), dead-peer detection, reconnection with
 *    backoff, rekeying by fresh handshake — exactly like `shaip run`.
 *  - shaip_tunnel_*: one bare session, no keepalive or reconnect (probes,
 *    tests).
 *
 * Conventions:
 *  - Every call is NULL-safe; a Rust panic never unwinds into C.
 *  - `err` may be NULL; otherwise, on failure it receives a heap-allocated
 *    message to release with shaip_string_free().
 *  - Strings returned by this library are released with shaip_string_free().
 *  - One thread may call shaip_tunnel_send() while another calls
 *    shaip_tunnel_recv() on the same tunnel.
 *
 * Link: libshaip_ffi.a (static, e.g. iOS) or libshaip_ffi.so / .dylib / .dll.
 */
#ifndef SHAIP_H
#define SHAIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A receive buffer of this size always fits one packet. */
#define SHAIP_MAX_PACKET 65535

typedef struct ShaipTunnel ShaipTunnel;

typedef struct ShaipStats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t packets_received;
    uint64_t bytes_received;
    uint64_t packets_dropped; /* datagrams that did not open: replay, tamper, foreign */
} ShaipStats;

/* Library version (static; do not free). */
const char *shaip_version(void);

/*
 * Handshake with a shaipd server and wait until it confirms the session.
 * server:                "host:port" of the UDP listener.
 * server_*_pub_hex:      the pins printed by `shaipd --identity <f> --print-public`.
 * identity_path:         this device's identity file (created 0600 if absent).
 * device_cert_path:      certificate from enrollment, or NULL (open servers).
 * Returns NULL on failure — including a device-bound server that does not
 * admit this device (unenrolled or revoked).
 */
ShaipTunnel *shaip_tunnel_connect(const char *server,
                                    const char *server_ml_dsa_pub_hex,
                                    const char *server_ed_pub_hex,
                                    const char *identity_path,
                                    const char *device_cert_path,
                                    uint32_t timeout_ms,
                                    char **err);

/* Send one IP packet. Returns 0, or -1 on error. */
int shaip_tunnel_send(const ShaipTunnel *t, const uint8_t *pkt, size_t len, char **err);

/* Receive one IP packet. Returns its length, 0 on timeout, -1 on error. */
long shaip_tunnel_recv(const ShaipTunnel *t, uint8_t *buf, size_t cap,
                        uint32_t timeout_ms, char **err);

/* Server-assigned tunnel address, host order (0x0A4D0002 = 10.77.0.2); 0 if none. */
uint32_t shaip_tunnel_assigned_ipv4(const ShaipTunnel *t);

/* Copy the traffic counters. Returns 0, or -1 if an argument is NULL. */
int shaip_tunnel_stats(const ShaipTunnel *t, ShaipStats *out);

/* Close and free a tunnel. NULL is a no-op. */
void shaip_tunnel_close(ShaipTunnel *t);

/*
 * Verify a shaip://enroll link (or bare token) against the pinned
 * enrollment-authority key, locally — for a deep-link handler's confirmation
 * prompt. Returns 0 and sets *account_out (free it), or -1.
 */
int shaip_enroll_link_verify(const char *link, const char *authority_pub_hex,
                              char **account_out, char **err);

/*
 * Enroll this device: verify the link, prove possession of the identity key,
 * then verify and store the certificate at "<identity_path>.cert".
 * Returns the device id (hex; free it), or NULL. `name` is reduced to a
 * platform label (iPhone, iPad, Android, Windows, Linux, Mac, or "device")
 * before anything is sent: pass the platform, never the user's device name.
 */
char *shaip_enroll(const char *link, const char *server,
                    const char *authority_pub_hex, const char *ca_pub_hex,
                    const char *identity_path, const char *name, char **err);

/* ---- Reconnecting session --------------------------------------------- */

typedef struct ShaipSession ShaipSession;

#define SHAIP_STATE_CONNECTED    0  /* a confirmed session carries traffic */
#define SHAIP_STATE_RECONNECTING 1  /* negotiating a new session; packets are dropped meanwhile */
#define SHAIP_STATE_STOPPED      2

typedef struct ShaipStatus {
    int32_t state;              /* SHAIP_STATE_* */
    uint32_t assigned_ipv4;     /* tunnel address, host order; 0 if none */
    uint8_t prefix_len;
    uint32_t gateway_ipv4;      /* the server's tunnel address; 0 if none */
    uint32_t dns_ipv4;          /* resolver to use (reached through the tunnel); 0: none pushed */
    uint16_t mtu;               /* MTU for the tunnel interface */
    uint32_t rtt_us;            /* smoothed keepalive RTT; 0 until measured */
    uint64_t up_since_unix_ms;  /* when the link came up (rekeys keep it); 0 while down */
    uint32_t reconnects;        /* sessions re-established after a failure */
    uint32_t rekeys;            /* sessions replaced by a scheduled rekey */
    ShaipStats stats;          /* totals across every session of this link */
    uint64_t dropped_offline;   /* outbound packets dropped while no session was up */
    uint8_t server_identity[16];/* the server's identity_id (as `shaipd --print-public` shows), proven by the handshake */
} ShaipStatus;

/*
 * Connect, wait for the server to confirm the first session, then keep the
 * link up in the background. Arguments as for shaip_tunnel_connect. NULL on
 * failure of the first connection (wrong pins, not admitted, unreachable).
 */
ShaipSession *shaip_session_start(const char *server,
                                    const char *server_ml_dsa_pub_hex,
                                    const char *server_ed_pub_hex,
                                    const char *identity_path,
                                    const char *device_cert_path,
                                    uint32_t timeout_ms,
                                    char **err);

/* Send one IP packet; dropped (and counted) while reconnecting. 0, or -1 for bad arguments. */
int shaip_session_send(const ShaipSession *s, const uint8_t *pkt, size_t len);

/* Receive one IP packet across reconnects: its length, 0 on timeout, -1 once stopped. */
long shaip_session_recv(const ShaipSession *s, uint8_t *buf, size_t cap,
                         uint32_t timeout_ms, char **err);

/* Copy a status snapshot. 0, or -1 if an argument is NULL. */
int shaip_session_status(const ShaipSession *s, ShaipStatus *out);

/* The server's UDP address as resolved and used, e.g. "203.0.113.7:443" (free it). */
char *shaip_session_server_addr(const ShaipSession *s);

/* Why the last session ended or the last attempt failed (free it), or NULL. */
char *shaip_session_last_error(const ShaipSession *s);

/* Renegotiate now, e.g. after the device changed networks. 0, or -1 if s is NULL. */
int shaip_session_reconnect(const ShaipSession *s);

/*
 * Close the session (telling the server) and stop reconnecting; blocked and
 * later shaip_session_recv calls return -1. The session stays allocated.
 */
void shaip_session_stop(const ShaipSession *s);

/* Free a session (stopping it first if needed). No other thread may be inside
 * a shaip_session_* call on it. NULL is a no-op. */
void shaip_session_free(ShaipSession *s);

/* Free a string returned by this library. NULL is a no-op. */
void shaip_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* SHAIP_H */
