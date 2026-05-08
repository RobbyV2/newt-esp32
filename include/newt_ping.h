#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "esp_netif_ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*newt_ping_on_reply_t)(const esp_ip4_addr_t *from,
                                     uint32_t elapsed_ms,
                                     void *ctx);

typedef struct {
    esp_ip4_addr_t       target;
    uint32_t             interval_ms;
    uint32_t             timeout_ms;
    uint32_t             max_attempts;
    newt_ping_on_reply_t on_reply;
    void                *ctx;
} newt_ping_config_t;

esp_err_t newt_ping_init(const newt_ping_config_t *cfg);
esp_err_t newt_ping_start(void);
esp_err_t newt_ping_stop(void);

#ifdef __cplusplus
}
#endif
