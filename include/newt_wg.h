#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "esp_err.h"
#include "esp_netif_ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEWT_WG_KEY_LEN      32
#define NEWT_WG_ENDPOINT_MAX 64

typedef struct {
    uint8_t priv[NEWT_WG_KEY_LEN];
    uint8_t pub[NEWT_WG_KEY_LEN];
} newt_wg_keypair_t;

typedef struct {
    uint8_t        server_pubkey[NEWT_WG_KEY_LEN];
    char           endpoint[NEWT_WG_ENDPOINT_MAX];
    uint16_t       endpoint_port;
    esp_ip4_addr_t server_ip;
    esp_ip4_addr_t tunnel_ip;
    esp_ip4_addr_t tunnel_netmask;
    uint16_t       keepalive_sec;
} newt_wg_config_t;

typedef enum {
    NEWT_WG_DOWN = 0,
    NEWT_WG_RESOLVING,
    NEWT_WG_HANDSHAKING,
    NEWT_WG_UP,
} newt_wg_state_t;

esp_err_t newt_wg_load_or_generate_keypair(newt_wg_keypair_t *out);

esp_err_t newt_wg_init(const newt_wg_config_t *cfg,
                       const newt_wg_keypair_t *kp);
esp_err_t newt_wg_start(void);
esp_err_t newt_wg_stop(void);

newt_wg_state_t newt_wg_get_state(void);
bool            newt_wg_is_connected(void);
esp_err_t       newt_wg_get_local_pubkey(uint8_t out[NEWT_WG_KEY_LEN]);
esp_err_t       newt_wg_get_tunnel_ip(esp_ip4_addr_t *out);

#ifdef __cplusplus
}
#endif
