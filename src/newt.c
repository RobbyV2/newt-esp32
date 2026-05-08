#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "newt.h"
#include "newt_auth.h"
#include "newt_ping.h"
#include "newt_proto.h"
#include "newt_wg.h"
#include "newt_ws.h"

ESP_EVENT_DEFINE_BASE(NEWT_EVENT);

static const char *TAG = "NEWT";

#define BIT_AUTHED        BIT0
#define BIT_WS_CONN       BIT1
#define BIT_WG_CONFIGURED BIT2
#define BIT_WG_UP         BIT3
#define BIT_STOP          BIT4

#define NEWT_SUPERVISOR_STACK   12288
#define NEWT_RECONNECT_STACK    8192
#define NEWT_PING_LOOP_STACK    4096
#define NEWT_SUPERVISOR_PRIO    5
#define NEWT_RECONNECT_PRIO     5
#define NEWT_PING_LOOP_PRIO     4

static newt_config_t s_cfg;
static char s_endpoint[256];
static char s_id[64];
static char s_secret[128];
static char s_token[NEWT_AUTH_TOKEN_MAX];
static newt_wg_keypair_t s_kp;
static newt_wg_config_t s_wg_cfg;
static esp_ip4_addr_t s_tunnel_ip;
static esp_ip4_addr_t s_server_ip;
static EventGroupHandle_t s_evt;
static TaskHandle_t s_supervisor;
static TaskHandle_t s_periodic_ping;

static void cb_ws_msg(const char *type, const char *data_json, size_t data_len, uint64_t cv, void *ctx) {
    (void)ctx;
    newt_proto_handle_message(type, data_json, data_len, cv);
}

static void cb_wg_connect(const newt_proto_wg_connect_t *cfg, void *ctx) {
    (void)ctx;
    memcpy(s_wg_cfg.server_pubkey, cfg->server_pubkey, NEWT_WG_KEY_LEN);
    strlcpy(s_wg_cfg.endpoint, cfg->endpoint, NEWT_WG_ENDPOINT_MAX);
    s_wg_cfg.endpoint_port = cfg->endpoint_port;
    inet_pton(AF_INET, cfg->server_ip, &s_wg_cfg.server_ip.addr);
    inet_pton(AF_INET, cfg->tunnel_ip, &s_wg_cfg.tunnel_ip.addr);
    s_wg_cfg.tunnel_netmask.addr = 0xFFFFFFFF;
    s_wg_cfg.keepalive_sec = 25;
    s_server_ip = s_wg_cfg.server_ip;
    s_tunnel_ip = s_wg_cfg.tunnel_ip;
    ESP_LOGI(TAG, "registered");
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_REGISTERED, NULL);
    xEventGroupSetBits(s_evt, BIT_WG_CONFIGURED);
}

static void reconnect_task(void *arg) {
    (void)arg;
    ESP_LOGI(TAG, "reconnect_task: tearing down WG");
    xEventGroupClearBits(s_evt, BIT_WG_UP | BIT_WG_CONFIGURED);
    newt_wg_stop();

    newt_proto_send_ping_request();
    {
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
        if (b & BIT_STOP) { vTaskDelete(NULL); return; }
    }
    newt_proto_send_register(s_kp.pub);

    EventBits_t bits = xEventGroupWaitBits(s_evt, BIT_WG_CONFIGURED | BIT_STOP, pdFALSE, pdFALSE, pdMS_TO_TICKS(60000));
    if (bits & BIT_STOP) {
        vTaskDelete(NULL);
        return;
    }
    if (!(bits & BIT_WG_CONFIGURED)) {
        ESP_LOGE(TAG, "reconnect: wg/connect timeout after 60s");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        vTaskDelete(NULL);
        return;
    }
    if (newt_wg_init(&s_wg_cfg, &s_kp) != ESP_OK) {
        ESP_LOGE(TAG, "reconnect: wg_init failed");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        vTaskDelete(NULL);
        return;
    }
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_WG_CONFIGURED, NULL);
    if (newt_wg_start() != ESP_OK) {
        ESP_LOGE(TAG, "reconnect: wg_start failed");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        vTaskDelete(NULL);
        return;
    }
    int wg_wait = 0;
    while (newt_wg_get_state() != NEWT_WG_UP && wg_wait < 120 && !(xEventGroupGetBits(s_evt) & BIT_STOP)) {
        vTaskDelay(pdMS_TO_TICKS(500));
        wg_wait++;
    }
    if (xEventGroupGetBits(s_evt) & BIT_STOP) {
        vTaskDelete(NULL);
        return;
    }
    if (newt_wg_get_state() != NEWT_WG_UP) {
        ESP_LOGE(TAG, "reconnect: wg handshake timeout");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        vTaskDelete(NULL);
        return;
    }
    xEventGroupSetBits(s_evt, BIT_WG_UP);
    ESP_LOGI(TAG, "reconnect: WG handshake complete");
    if (s_cfg.on_event) {
        s_cfg.on_event(NEWT_EVT_REGISTERED, NULL);
        s_cfg.on_event(NEWT_EVT_WG_HANDSHAKED, NULL);
        s_cfg.on_event(NEWT_EVT_ONLINE, NULL);
    }
    vTaskDelete(NULL);
}

static void cb_wg_reconnect(void *ctx) {
    (void)ctx;
    ESP_LOGW(TAG, "wg reconnect requested");
    xTaskCreate(reconnect_task, "newt_reconn", NEWT_RECONNECT_STACK, NULL, NEWT_RECONNECT_PRIO, NULL);
}

static void cb_wg_terminate(void *ctx) {
    (void)ctx;
    ESP_LOGW(TAG, "wg terminate requested");
    xEventGroupSetBits(s_evt, BIT_STOP);
}

static void cb_exit_nodes(void *ctx) {
    (void)ctx;
}

static void cb_ping_reply(const esp_ip4_addr_t *from, uint32_t elapsed_ms, void *ctx) {
    (void)elapsed_ms;
    (void)ctx;
    ESP_LOGI(TAG, "ping reply from " IPSTR, IP2STR(from));
}

static void periodic_ping_task(void *arg) {
    (void)arg;
    for (;;) {
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(20000));
        if (b & BIT_STOP) break;
        newt_proto_send_ping();
    }
    s_periodic_ping = NULL;
    vTaskDelete(NULL);
}

static void supervisor_task(void *arg) {
    (void)arg;

    int auth_attempts = 0;
    while (auth_attempts < 10) {
        size_t tok_len = 0;
        esp_err_t r = newt_auth_get_token(s_cfg.endpoint, s_cfg.newt_id, s_cfg.newt_secret,
                                          s_token, NEWT_AUTH_TOKEN_MAX, &tok_len);
        if (r == ESP_OK) {
            ESP_LOGI(TAG, "AUTHED");
            xEventGroupSetBits(s_evt, BIT_AUTHED);
            if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_AUTHED, NULL);
            break;
        }
        ESP_LOGW(TAG, "auth failed err=%s (check newt_id/newt_secret/endpoint and SNTP sync), retry in 5s", esp_err_to_name(r));
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
        if (b & BIT_STOP) goto err;
        auth_attempts++;
    }
    if (auth_attempts >= 10) {
        ESP_LOGE(TAG, "auth failed permanently after %d attempts; verify Pangolin credentials and endpoint URL", auth_attempts);
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        goto err;
    }

    newt_ws_config_t ws_cfg = {
        .endpoint = s_cfg.endpoint,
        .token = s_token,
        .on_msg = cb_ws_msg,
        .ctx = NULL,
    };
    if (newt_ws_init(&ws_cfg) != ESP_OK) goto err;
    if (newt_ws_start() != ESP_OK) goto err;
    int ws_wait = 0;
    while (!newt_ws_is_connected() && ws_wait < 60) {
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(500));
        if (b & BIT_STOP) goto err;
        ws_wait++;
    }
    if (!newt_ws_is_connected()) {
        ESP_LOGE(TAG, "WS connect timeout after 30s; check endpoint reachability and TLS bundle");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        goto err;
    }
    xEventGroupSetBits(s_evt, BIT_WS_CONN);
    ESP_LOGI(TAG, "WS_CONNECTED");
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_WS_CONNECTED, NULL);

    newt_proto_send_ping_request();
    {
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
        if (b & BIT_STOP) goto err;
    }
    newt_proto_send_register(s_kp.pub);

    EventBits_t bits = xEventGroupWaitBits(s_evt, BIT_WG_CONFIGURED | BIT_STOP, pdFALSE, pdFALSE, pdMS_TO_TICKS(60000));
    if (bits & BIT_STOP) goto err;
    if (!(bits & BIT_WG_CONFIGURED)) {
        ESP_LOGE(TAG, "wg/connect timeout after 60s; Pangolin did not return wg connect message");
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        goto err;
    }
    if (newt_wg_init(&s_wg_cfg, &s_kp) != ESP_OK) goto err;
    ESP_LOGI(TAG, "WG_CONFIGURED");
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_WG_CONFIGURED, NULL);

    if (newt_wg_start() != ESP_OK) goto err;
    int wg_wait = 0;
    while (newt_wg_get_state() != NEWT_WG_UP && wg_wait < 120) {
        EventBits_t b = xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, pdMS_TO_TICKS(500));
        if (b & BIT_STOP) goto err;
        wg_wait++;
    }
    if (newt_wg_get_state() != NEWT_WG_UP) {
        ESP_LOGE(TAG, "wg handshake timeout after 60s; verify UDP %u reachability to %s", (unsigned)s_wg_cfg.endpoint_port, s_wg_cfg.endpoint);
        if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ERROR, NULL);
        goto err;
    }
    xEventGroupSetBits(s_evt, BIT_WG_UP);
    ESP_LOGI(TAG, "WG handshake complete");
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_WG_HANDSHAKED, NULL);

    ESP_LOGI(TAG, "ONLINE");
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_ONLINE, NULL);

    newt_ping_config_t ping_cfg = {
        .target = s_server_ip,
        .interval_ms = 2000,
        .timeout_ms = 1000,
        .max_attempts = 0,
        .on_reply = cb_ping_reply,
        .ctx = NULL,
    };
    newt_ping_init(&ping_cfg);
    newt_ping_start();
    xTaskCreate(periodic_ping_task, "newt_ping_loop", NEWT_PING_LOOP_STACK, NULL, NEWT_PING_LOOP_PRIO, &s_periodic_ping);

    xEventGroupWaitBits(s_evt, BIT_STOP, pdFALSE, pdTRUE, portMAX_DELAY);

err:
    s_supervisor = NULL;
    vTaskDelete(NULL);
}

esp_err_t newt_init(const newt_config_t *cfg) {
    if (!cfg || !cfg->endpoint || !cfg->newt_id || !cfg->newt_secret) return ESP_ERR_INVALID_ARG;

    strlcpy(s_endpoint, cfg->endpoint, sizeof(s_endpoint));
    strlcpy(s_id, cfg->newt_id, sizeof(s_id));
    strlcpy(s_secret, cfg->newt_secret, sizeof(s_secret));
    s_cfg = *cfg;
    s_cfg.endpoint = s_endpoint;
    s_cfg.newt_id = s_id;
    s_cfg.newt_secret = s_secret;

    nvs_handle_t h;
    esp_err_t r = nvs_open("newt", NVS_READWRITE, &h);
    if (r != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed err=%s (call nvs_flash_init() before newt_init)", esp_err_to_name(r));
        return r;
    }
    nvs_close(h);

    if (newt_wg_load_or_generate_keypair(&s_kp) != ESP_OK) return ESP_FAIL;

    newt_proto_callbacks_t pcb = {
        .on_wg_connect = cb_wg_connect,
        .on_wg_reconnect = cb_wg_reconnect,
        .on_wg_terminate = cb_wg_terminate,
        .on_exit_nodes = cb_exit_nodes,
        .ctx = NULL,
    };
    if (newt_proto_init(&pcb) != ESP_OK) return ESP_FAIL;

    s_evt = xEventGroupCreate();
    if (!s_evt) return ESP_ERR_NO_MEM;

    return ESP_OK;
}

esp_err_t newt_start(void) {
    if (!s_evt) {
        ESP_LOGE(TAG, "newt_start called before newt_init");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_supervisor) return ESP_ERR_INVALID_STATE;
    BaseType_t r = xTaskCreate(supervisor_task, "newt_sup", NEWT_SUPERVISOR_STACK, NULL, NEWT_SUPERVISOR_PRIO, &s_supervisor);
    return (r == pdPASS) ? ESP_OK : ESP_FAIL;
}

esp_err_t newt_stop(void) {
    if (!s_evt) return ESP_OK;
    xEventGroupSetBits(s_evt, BIT_STOP);
    newt_ws_stop();
    newt_wg_stop();
    newt_ping_stop();
    mbedtls_platform_zeroize(s_secret, sizeof(s_secret));
    mbedtls_platform_zeroize(s_token, sizeof(s_token));
    mbedtls_platform_zeroize(s_kp.priv, sizeof(s_kp.priv));
    if (s_cfg.on_event) s_cfg.on_event(NEWT_EVT_OFFLINE, NULL);
    return ESP_OK;
}

esp_err_t newt_get_tunnel_ip(esp_ip4_addr_t *out) {
    if (!out) return ESP_ERR_INVALID_ARG;
    if (s_tunnel_ip.addr == 0) return ESP_ERR_INVALID_STATE;
    *out = s_tunnel_ip;
    return ESP_OK;
}
