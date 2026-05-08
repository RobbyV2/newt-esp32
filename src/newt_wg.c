#include "newt_wg.h"

#include <string.h>
#include <stdio.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/tcpip.h"

#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"

#include "esp_wireguard.h"

extern int crypto_scalarmult_curve25519(unsigned char *q,
                                        const unsigned char *n,
                                        const unsigned char *p);

static const char *TAG = "WG";
static const char *NVS_NS = "newt";
static const char *NVS_KEY = "wg_priv";

#define WG_POLL_STACK 4096
#define WG_POLL_PRIO  5

static wireguard_ctx_t  s_ctx;
static wireguard_config_t s_wg_cfg;
static char             s_priv_b64[48];
static char             s_pub_b64[48];
static char             s_server_pub_b64[48];
static char             s_addr_str[16];
static char             s_mask_str[16];
static char             s_server_ip_str[16];
static newt_wg_state_t  s_state = NEWT_WG_DOWN;
static esp_ip4_addr_t   s_tunnel_ip;
static uint8_t          s_local_pub[NEWT_WG_KEY_LEN];
static TaskHandle_t     s_poller = NULL;
static SemaphoreHandle_t s_poller_done = NULL;
static volatile bool    s_poller_stop_requested = false;

typedef esp_err_t (*wg_fn_t)(void *);

typedef struct {
    wg_fn_t           fn;
    void             *arg;
    esp_err_t         result;
    SemaphoreHandle_t done;
} wg_call_ctx_t;

static void wg_call_trampoline(void *arg) {
    wg_call_ctx_t *c = (wg_call_ctx_t *)arg;
    c->result = c->fn(c->arg);
    xSemaphoreGive(c->done);
}

static esp_err_t wg_call_on_tcpip(wg_fn_t fn, void *arg) {
    wg_call_ctx_t c = {
        .fn = fn,
        .arg = arg,
        .result = ESP_FAIL,
        .done = xSemaphoreCreateBinary(),
    };
    if (c.done == NULL) {
        return ESP_ERR_NO_MEM;
    }
    err_t e = tcpip_callback(wg_call_trampoline, &c);
    if (e != ERR_OK) {
        vSemaphoreDelete(c.done);
        return ESP_FAIL;
    }
    xSemaphoreTake(c.done, portMAX_DELAY);
    vSemaphoreDelete(c.done);
    return c.result;
}

static esp_err_t wg_init_impl(void *arg)       { (void)arg; return esp_wireguard_init(&s_wg_cfg, &s_ctx); }
static esp_err_t wg_connect_impl(void *arg)    { (void)arg; return esp_wireguard_connect(&s_ctx); }
static esp_err_t wg_disconnect_impl(void *arg) { (void)arg; return esp_wireguard_disconnect(&s_ctx); }
static esp_err_t wg_peer_up_impl(void *arg)    { (void)arg; return esp_wireguard_peer_is_up(&s_ctx); }
static esp_err_t wg_add_server_ip_impl(void *arg) { (void)arg; return esp_wireguard_add_allowed_ip(&s_ctx, s_server_ip_str, "255.255.255.255"); }

static void ip4_to_str(esp_ip4_addr_t a, char *out, size_t n) {
    uint32_t v = a.addr;
    snprintf(out, n, "%u.%u.%u.%u",
             (unsigned)((v) & 0xff),
             (unsigned)((v >> 8) & 0xff),
             (unsigned)((v >> 16) & 0xff),
             (unsigned)((v >> 24) & 0xff));
}

static esp_err_t b64_encode_key(const uint8_t *raw, char *out, size_t out_sz) {
    size_t olen = 0;
    int r = mbedtls_base64_encode((unsigned char *)out, out_sz, &olen, raw, NEWT_WG_KEY_LEN);
    if (r != 0) {
        return ESP_FAIL;
    }
    out[olen] = '\0';
    return ESP_OK;
}

static void clamp_x25519(uint8_t *k) {
    k[0]  &= 248;
    k[31] = (k[31] & 127) | 64;
}

esp_err_t newt_wg_load_or_generate_keypair(newt_wg_keypair_t *out) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed err=%d", err);
        return ESP_FAIL;
    }
    size_t len = NEWT_WG_KEY_LEN;
    err = nvs_get_blob(h, NVS_KEY, out->priv, &len);
    if (err != ESP_OK || len != NEWT_WG_KEY_LEN) {
        esp_fill_random(out->priv, NEWT_WG_KEY_LEN);
        clamp_x25519(out->priv);
        err = nvs_set_blob(h, NVS_KEY, out->priv, NEWT_WG_KEY_LEN);
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "nvs persist failed err=%d", err);
            nvs_close(h);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "generated new wg_priv");
    } else {
        ESP_LOGI(TAG, "loaded wg_priv from nvs");
    }
    nvs_close(h);

    static const uint8_t basepoint[NEWT_WG_KEY_LEN] = { 9 };
    (void)crypto_scalarmult_curve25519(out->pub, out->priv, basepoint);

    memcpy(s_local_pub, out->pub, NEWT_WG_KEY_LEN);

    ESP_LOGI(TAG, "pubkey=%02x%02x...", out->pub[0], out->pub[1]);
    return ESP_OK;
}

esp_err_t newt_wg_init(const newt_wg_config_t *cfg, const newt_wg_keypair_t *kp) {
    if (cfg == NULL || kp == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (b64_encode_key(kp->priv, s_priv_b64, sizeof(s_priv_b64)) != ESP_OK) {
        return ESP_FAIL;
    }
    if (b64_encode_key(kp->pub, s_pub_b64, sizeof(s_pub_b64)) != ESP_OK) {
        return ESP_FAIL;
    }
    if (b64_encode_key(cfg->server_pubkey, s_server_pub_b64, sizeof(s_server_pub_b64)) != ESP_OK) {
        return ESP_FAIL;
    }

    ip4_to_str(cfg->tunnel_ip,      s_addr_str, sizeof(s_addr_str));
    ip4_to_str(cfg->tunnel_netmask, s_mask_str, sizeof(s_mask_str));
    ip4_to_str(cfg->server_ip,      s_server_ip_str, sizeof(s_server_ip_str));

    memset(&s_wg_cfg, 0, sizeof(s_wg_cfg));
    s_wg_cfg.private_key          = s_priv_b64;
    s_wg_cfg.listen_port          = 0;
    s_wg_cfg.fw_mark              = 0;
    s_wg_cfg.public_key           = s_server_pub_b64;
    s_wg_cfg.preshared_key        = NULL;
    s_wg_cfg.address              = s_addr_str;
    s_wg_cfg.netmask              = s_mask_str;
    s_wg_cfg.endpoint             = cfg->endpoint;
    s_wg_cfg.port                 = cfg->endpoint_port;
    s_wg_cfg.persistent_keepalive = cfg->keepalive_sec;

    s_tunnel_ip = cfg->tunnel_ip;

    esp_err_t err = wg_call_on_tcpip(wg_init_impl, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init failed err=%d", err);
        return err;
    }
    s_state = NEWT_WG_RESOLVING;
    ESP_LOGI(TAG, "init done");
    return ESP_OK;
}

static void wg_poll_task(void *arg) {
    (void)arg;
    while (1) {
        if (s_poller_stop_requested) {
            xSemaphoreGive(s_poller_done);
            vTaskDelete(NULL);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (s_poller_stop_requested) {
            xSemaphoreGive(s_poller_done);
            vTaskDelete(NULL);
            return;
        }
        esp_err_t r = wg_call_on_tcpip(wg_peer_up_impl, NULL);
        if (r == ESP_OK) {
            s_state = NEWT_WG_UP;
            ESP_LOGI(TAG, "handshake complete");
            xSemaphoreGive(s_poller_done);
            vTaskDelete(NULL);
            return;
        }
    }
}

esp_err_t newt_wg_start(void) {
    int attempts = 0;
    esp_err_t err;
    while (1) {
        err = wg_call_on_tcpip(wg_connect_impl, NULL);
        if (err == ESP_OK) {
            break;
        }
        if (err == ESP_ERR_RETRY && attempts < 10) {
            attempts++;
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }
        ESP_LOGE(TAG, "connect failed err=%d", err);
        return ESP_FAIL;
    }
    esp_err_t aerr = wg_call_on_tcpip(wg_add_server_ip_impl, NULL);
    if (aerr != ESP_OK) {
        ESP_LOGW(TAG, "add_allowed_ip server=%s failed err=%d", s_server_ip_str, aerr);
    } else {
        ESP_LOGI(TAG, "added allowed_ip %s/32", s_server_ip_str);
    }
    s_state = NEWT_WG_HANDSHAKING;
    if (s_poller_done == NULL) {
        s_poller_done = xSemaphoreCreateBinary();
        if (s_poller_done == NULL) {
            ESP_LOGE(TAG, "poller done semaphore alloc failed");
            return ESP_ERR_NO_MEM;
        }
    }
    s_poller_stop_requested = false;
    BaseType_t ok = xTaskCreate(wg_poll_task, "wg_poll", WG_POLL_STACK, NULL, WG_POLL_PRIO, &s_poller);
    if (ok != pdPASS) {
        s_poller = NULL;
        ESP_LOGE(TAG, "poll task spawn failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t newt_wg_stop(void) {
    if (s_poller != NULL) {
        s_poller_stop_requested = true;
        if (s_poller_done != NULL) {
            (void)xSemaphoreTake(s_poller_done, pdMS_TO_TICKS(3000));
        }
        s_poller = NULL;
    }
    if (s_poller_done != NULL) {
        vSemaphoreDelete(s_poller_done);
        s_poller_done = NULL;
    }
    s_poller_stop_requested = false;
    esp_err_t err = wg_call_on_tcpip(wg_disconnect_impl, NULL);
    s_state = NEWT_WG_DOWN;
    mbedtls_platform_zeroize(s_priv_b64, sizeof(s_priv_b64));
    ESP_LOGI(TAG, "disconnected");
    return err;
}

newt_wg_state_t newt_wg_get_state(void) {
    return s_state;
}

bool newt_wg_is_connected(void) {
    return s_state == NEWT_WG_UP;
}

esp_err_t newt_wg_get_local_pubkey(uint8_t out[NEWT_WG_KEY_LEN]) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(out, s_local_pub, NEWT_WG_KEY_LEN);
    return ESP_OK;
}

esp_err_t newt_wg_get_tunnel_ip(esp_ip4_addr_t *out) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_tunnel_ip.addr == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    out->addr = s_tunnel_ip.addr;
    return ESP_OK;
}
