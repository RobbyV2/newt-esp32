#pragma once

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif_ip_addr.h"

#include "newt_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

ESP_EVENT_DECLARE_BASE(NEWT_EVENT);

typedef enum {
    NEWT_EVT_AUTHED = 0,
    NEWT_EVT_WS_CONNECTED,
    NEWT_EVT_REGISTERED,
    NEWT_EVT_WG_CONFIGURED,
    NEWT_EVT_WG_HANDSHAKED,
    NEWT_EVT_ONLINE,
    NEWT_EVT_OFFLINE,
    NEWT_EVT_ERROR,
} newt_event_t;

typedef void (*newt_event_cb_t)(newt_event_t evt, void *data);

typedef struct {
    const char *endpoint;
    const char *newt_id;
    const char *newt_secret;
    newt_event_cb_t on_event;
} newt_config_t;

esp_err_t newt_init(const newt_config_t *cfg);
esp_err_t newt_start(void);
esp_err_t newt_stop(void);
esp_err_t newt_get_tunnel_ip(esp_ip4_addr_t *out);

#ifdef __cplusplus
}
#endif
