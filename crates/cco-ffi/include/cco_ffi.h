#ifndef CCO_FFI_H
#define CCO_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque thread-safe handle to a running split WireGuard + MCC overlay tunnel. */
typedef struct CcoTunnelHandle CcoTunnelHandle;

/* Optional platform socket protector callback (e.g. Android VpnService.protect). */
typedef bool (*cco_protect_socket_cb)(int32_t fd, void *ctx);

/* Returns library version as a heap-allocated UTF-8 C string (free with cco_string_free). */
char *cco_version(void);

/* Frees any UTF-8 C string returned by cco_ffi functions. Safe on NULL. */
void cco_string_free(char *ptr);

/* Fail-closed verification of a Trust Registry v2 bundle against a pinned Trust Root v1.
 * required_nodes_json: JSON array of required node names, e.g. '["A","X1","X2","B"]'.
 * Returns JSON: {"ok":true,"data":{...}} or {"ok":false,"error":"<code>"}. */
char *cco_verify_trust_bundle(
    const char *registry_json,
    const char *root_json,
    const char *required_nodes_json
);

/* Computes Chapter 3 exact route combinatorics (F1/I2P/F3/F4), compromise probabilities,
 * exact n50 thresholds, and rayon Monte Carlo cross-check.
 * Returns JSON: {"ok":true,"data":{...}} or {"ok":false,"error":"<code>"}. */
char *cco_analytics_summary(uint32_t n, uint32_t m, uint32_t j);

/* Generates a self-contained ephemeral RFC 5737 4-node demo bundle (for local testing & UI preview).
 * Returns JSON: {"ok":true,"data":{...}} or {"ok":false,"error":"<code>"}. */
char *cco_generate_demo_bundle(const char *local_node, const char *peer_node);

/* Starts a split WireGuard + MCC overlay tunnel using an in-memory IP packet channel
 * (used by Windows Wintun adapter bridges and cross-platform integration tests).
 * On error returns NULL and writes a heap-allocated error code into *err_out (free with cco_string_free). */
CcoTunnelHandle *cco_tunnel_start_channel(
    const char *config_json,
    char **err_out
);

/* Starts a split WireGuard + MCC overlay tunnel attached to an OS TUN file descriptor
 * (Android VpnService.detachFd(), Linux /dev/net/tun, macOS utun). Takes ownership of tun_fd on success. */
CcoTunnelHandle *cco_tunnel_start_fd(
    const char *config_json,
    int32_t tun_fd,
    cco_protect_socket_cb protect_cb,
    void *protect_ctx,
    char **err_out
);

/* Proactively sends a WireGuard Type 1 Handshake Initiation through the MCC overlay. Returns 0 on success. */
int32_t cco_tunnel_initiate(CcoTunnelHandle *handle);

/* Pushes one outbound L3 IPv4/IPv6 packet from the OS TUN (e.g. Windows Wintun) into the tunnel.
 * Returns 0 on success, 1 if queue is full (WouldBlock), -1 on error. */
int32_t cco_tunnel_push_outbound_ip(
    CcoTunnelHandle *handle,
    const uint8_t *data,
    size_t len
);

/* Non-blocking pop of one decrypted inbound L3 IPv4/IPv6 packet for the OS TUN (e.g. Windows Wintun).
 * Returns >0 (packet byte length), 0 if no packet ready, or -1 on error / buffer too small. */
intptr_t cco_tunnel_pop_inbound_ip(
    CcoTunnelHandle *handle,
    uint8_t *out_buf,
    size_t capacity
);

/* Returns JSON snapshot of live TunnelStats (free with cco_string_free). */
char *cco_tunnel_stats(CcoTunnelHandle *handle);

/* Drains and returns JSON array of SanitizedEvent items (free with cco_string_free). */
char *cco_tunnel_drain_events(CcoTunnelHandle *handle);

/* Stops the tunnel, shuts down sockets/runtime, and frees the handle. Safe on NULL. */
void cco_tunnel_stop(CcoTunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* CCO_FFI_H */
