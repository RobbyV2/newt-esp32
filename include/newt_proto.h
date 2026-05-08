#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#include "newt_wg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEWT_PROTO_ENDPOINT_MAX 128

typedef struct {
    char     endpoint[NEWT_PROTO_ENDPOINT_MAX];
    uint16_t endpoint_port;
    uint8_t  server_pubkey[NEWT_WG_KEY_LEN];
    char     server_ip[16];
    char     tunnel_ip[16];
} newt_proto_wg_connect_t;

typedef void (*newt_proto_on_wg_connect_t)(const newt_proto_wg_connect_t *cfg, void *ctx);
typedef void (*newt_proto_on_wg_reconnect_t)(void *ctx);
typedef void (*newt_proto_on_wg_terminate_t)(void *ctx);
typedef void (*newt_proto_on_exit_nodes_t)(void *ctx);

typedef struct {
    newt_proto_on_wg_connect_t   on_wg_connect;
    newt_proto_on_wg_reconnect_t on_wg_reconnect;
    newt_proto_on_wg_terminate_t on_wg_terminate;
    newt_proto_on_exit_nodes_t   on_exit_nodes;
    void *ctx;
} newt_proto_callbacks_t;

esp_err_t newt_proto_init(const newt_proto_callbacks_t *cb);
uint64_t  newt_proto_get_config_version(void);

esp_err_t newt_proto_handle_message(const char *type,
                                    const char *data_json,
                                    size_t data_len,
                                    uint64_t config_version);

esp_err_t newt_proto_send_ping_request(void);
esp_err_t newt_proto_send_register(const uint8_t local_pubkey[NEWT_WG_KEY_LEN]);
esp_err_t newt_proto_send_ping(void);
esp_err_t newt_proto_send_disconnecting(void);

#ifdef __cplusplus
}
#endif
