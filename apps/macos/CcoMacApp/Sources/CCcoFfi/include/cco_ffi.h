#ifndef CCO_FFI_H
#define CCO_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CcoTunnelHandle CcoTunnelHandle;
typedef bool (*cco_protect_socket_cb)(int32_t fd, void *ctx);

char *cco_version(void);
void cco_string_free(char *ptr);

char *cco_verify_trust_bundle(
    const char *registry_json,
    const char *root_json,
    const char *required_nodes_json
);

char *cco_analytics_summary(uint32_t n, uint32_t m, uint32_t j);
char *cco_generate_demo_bundle(const char *local_node, const char *peer_node);

CcoTunnelHandle *cco_tunnel_start_channel(
    const char *config_json,
    char **err_out
);

CcoTunnelHandle *cco_tunnel_start_fd(
    const char *config_json,
    int32_t tun_fd,
    cco_protect_socket_cb protect_cb,
    void *protect_ctx,
    char **err_out
);

int32_t cco_tunnel_initiate(CcoTunnelHandle *handle);
int32_t cco_tunnel_push_outbound_ip(CcoTunnelHandle *handle, const uint8_t *data, size_t len);
intptr_t cco_tunnel_pop_inbound_ip(CcoTunnelHandle *handle, uint8_t *out_buf, size_t capacity);
char *cco_tunnel_stats(CcoTunnelHandle *handle);
char *cco_tunnel_drain_events(CcoTunnelHandle *handle);
void cco_tunnel_stop(CcoTunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* CCO_FFI_H */
