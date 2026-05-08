#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEWT_AUTH_TOKEN_MAX 512
#define NEWT_AUTH_ID_MAX     64
#define NEWT_AUTH_SECRET_MAX 96

esp_err_t newt_auth_get_token(const char *endpoint,
                              const char *newt_id,
                              const char *newt_secret,
                              char *out_token,
                              size_t out_token_size,
                              size_t *out_token_len);

esp_err_t newt_auth_register_with_provisioning_key(const char *endpoint,
                                                   const char *provisioning_key,
                                                   const char *name,
                                                   char *out_id,
                                                   size_t out_id_size,
                                                   size_t *out_id_len,
                                                   char *out_secret,
                                                   size_t out_secret_size,
                                                   size_t *out_secret_len);

#ifdef __cplusplus
}
#endif
