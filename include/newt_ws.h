#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*newt_ws_on_message_t)(const char *type,
                                     const char *data_json,
                                     size_t data_len,
                                     uint64_t config_version,
                                     void *ctx);

typedef struct {
    const char *endpoint;
    const char *token;
    newt_ws_on_message_t on_msg;
    void *ctx;
} newt_ws_config_t;

esp_err_t newt_ws_init(const newt_ws_config_t *cfg);
esp_err_t newt_ws_start(void);
esp_err_t newt_ws_stop(void);
bool      newt_ws_is_connected(void);
esp_err_t newt_ws_send_envelope(const char *type, const char *data_json);

#ifdef __cplusplus
}
#endif
