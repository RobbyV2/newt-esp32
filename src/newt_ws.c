#include "newt_ws.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_crt_bundle.h"
#include "esp_websocket_client.h"

#include "cJSON.h"

#include "newt_proto.h"

static const char *TAG = "WS";

#define WS_QUEUE_DEPTH      8
#define WS_WORKER_PRIO      5
#define WS_WORKER_STACK     8192
#define WS_TASK_STACK       8192
#define WS_BUFFER_SIZE      2048
#define WS_PING_INTERVAL    10
#define WS_PINGPONG_TIMEOUT 60
#define WS_NETWORK_TIMEOUT  10000
#define WS_SEND_TIMEOUT_MS  2000
#define WS_URL_MAX          512
#define WS_RX_MAX           65536

typedef struct {
    char  *buf;
    size_t len;
} ws_msg_t;

static const int s_backoff_ms[] = {1000, 2000, 5000, 10000, 30000};
static const int s_backoff_n    = sizeof(s_backoff_ms) / sizeof(s_backoff_ms[0]);

static esp_websocket_client_handle_t s_client;
static newt_ws_config_t              s_cfg;
static char                         *s_endpoint;
static char                         *s_token;
static QueueHandle_t                 s_queue;
static TaskHandle_t                  s_worker;
static SemaphoreHandle_t             s_worker_done;
static volatile bool                 s_worker_stop_requested;
static int                           s_attempt;
static char                         *s_rx_assembly;
static size_t                        s_rx_assembly_len;
static size_t                        s_rx_assembly_cap;
static char                          s_url[WS_URL_MAX];

static char *url_encode(const char *src) {
    size_t n = strlen(src);
    char *out = malloc(n * 3 + 1);
    if (!out) return NULL;
    char *p = out;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            *p++ = (char)c;
        } else {
            sprintf(p, "%%%02X", c);
            p += 3;
        }
    }
    *p = '\0';
    return out;
}

static esp_err_t build_ws_url(const char *endpoint, const char *token, char *out, size_t out_sz) {
    const char *host = endpoint;
    if (strncmp(endpoint, "https://", 8) == 0) host = endpoint + 8;
    else if (strncmp(endpoint, "http://", 7) == 0) host = endpoint + 7;
    size_t hlen = strlen(host);
    while (hlen > 0 && host[hlen - 1] == '/') hlen--;
    char *enc = url_encode(token);
    if (!enc) return ESP_ERR_NO_MEM;
    int n = snprintf(out, out_sz, "wss://%.*s/api/v1/ws?token=%s&clientType=newt", (int)hlen, host, enc);
    free(enc);
    if (n < 0 || (size_t)n >= out_sz) return ESP_ERR_INVALID_SIZE;
    return ESP_OK;
}

static void worker_task(void *arg) {
    (void)arg;
    ws_msg_t msg;
    for (;;) {
        if (s_worker_stop_requested) {
            xSemaphoreGive(s_worker_done);
            vTaskDelete(NULL);
            return;
        }
        if (xQueueReceive(s_queue, &msg, portMAX_DELAY) != pdTRUE) continue;
        if (s_worker_stop_requested) {
            if (msg.buf) free(msg.buf);
            xSemaphoreGive(s_worker_done);
            vTaskDelete(NULL);
            return;
        }
        if (!msg.buf) continue;
        cJSON *root = cJSON_ParseWithLength(msg.buf, msg.len);
        if (!root) {
            ESP_LOGW(TAG, "json parse failed");
            free(msg.buf);
            continue;
        }
        cJSON *jtype = cJSON_GetObjectItemCaseSensitive(root, "type");
        cJSON *jdata = cJSON_GetObjectItemCaseSensitive(root, "data");
        cJSON *jver  = cJSON_GetObjectItemCaseSensitive(root, "configVersion");
        if (cJSON_IsString(jtype) && jtype->valuestring && s_cfg.on_msg) {
            char *data_str = NULL;
            size_t data_len = 0;
            if (cJSON_IsObject(jdata) || cJSON_IsArray(jdata)) {
                data_str = cJSON_PrintUnformatted(jdata);
                if (data_str) data_len = strlen(data_str);
            }
            uint64_t ver = 0;
            if (cJSON_IsNumber(jver)) ver = (uint64_t)jver->valuedouble;
            ESP_LOGD(TAG, "rx type=%s data_len=%zu cv=%llu", jtype->valuestring, data_str ? data_len : 2, (unsigned long long)ver);
            s_cfg.on_msg(jtype->valuestring, data_str ? data_str : "{}", data_str ? data_len : 2, ver, s_cfg.ctx);
            if (data_str) free(data_str);
        }
        cJSON_Delete(root);
        free(msg.buf);
    }
}

static void enqueue_payload(const char *buf, size_t len) {
    char *copy = malloc(len + 1);
    if (!copy) {
        ESP_LOGW(TAG, "rx alloc failed len=%u", (unsigned)len);
        return;
    }
    memcpy(copy, buf, len);
    copy[len] = '\0';
    ws_msg_t msg = { .buf = copy, .len = len };
    if (xQueueSend(s_queue, &msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "queue full, dropping frame len=%u", (unsigned)len);
        free(copy);
    }
}

static void handle_text_frame(esp_websocket_event_data_t *d) {
    if (d->payload_len > 0 && (size_t)d->payload_len > (size_t)d->data_len) {
        if (d->payload_offset == 0) {
            free(s_rx_assembly);
            s_rx_assembly = NULL;
            s_rx_assembly_len = 0;
            s_rx_assembly_cap = 0;
            if ((size_t)d->payload_len > WS_RX_MAX) {
                ESP_LOGW(TAG, "frame too large sz=%u max=%u, dropping", (unsigned)d->payload_len, (unsigned)WS_RX_MAX);
                return;
            }
            s_rx_assembly_cap = (size_t)d->payload_len;
            s_rx_assembly = malloc(s_rx_assembly_cap);
            if (!s_rx_assembly) {
                ESP_LOGW(TAG, "assembly alloc failed sz=%u", (unsigned)s_rx_assembly_cap);
                s_rx_assembly_cap = 0;
                return;
            }
        }
        if (!s_rx_assembly) return;
        if (s_rx_assembly_len + (size_t)d->data_len <= s_rx_assembly_cap) {
            memcpy(s_rx_assembly + s_rx_assembly_len, d->data_ptr, d->data_len);
            s_rx_assembly_len += (size_t)d->data_len;
        }
        if (s_rx_assembly_len >= s_rx_assembly_cap) {
            enqueue_payload(s_rx_assembly, s_rx_assembly_len);
            free(s_rx_assembly);
            s_rx_assembly = NULL;
            s_rx_assembly_cap = 0;
            s_rx_assembly_len = 0;
        }
        return;
    }
    enqueue_payload(d->data_ptr, (size_t)d->data_len);
}

static void apply_backoff(void) {
    int idx = s_attempt;
    if (idx >= s_backoff_n) idx = s_backoff_n - 1;
    int wait = s_backoff_ms[idx];
    if (s_client) esp_websocket_client_set_reconnect_timeout(s_client, wait);
    ESP_LOGW(TAG, "reconnecting backoff=%ds", wait / 1000);
    if (s_attempt < s_backoff_n - 1) s_attempt++;
}

static void ws_event_handler(void *arg, esp_event_base_t base, int32_t event_id, void *event_data) {
    (void)arg;
    (void)base;
    esp_websocket_event_data_t *d = (esp_websocket_event_data_t *)event_data;
    switch (event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "connected");
            s_attempt = 0;
            if (s_client) esp_websocket_client_set_reconnect_timeout(s_client, s_backoff_ms[0]);
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
        case WEBSOCKET_EVENT_ERROR:
            apply_backoff();
            break;
        case WEBSOCKET_EVENT_DATA:
            if (!d) break;
            if (d->op_code == 0x1) {
                handle_text_frame(d);
            } else if (d->op_code == 0x2) {
                ESP_LOGW(TAG, "binary frame dropped len=%d", d->data_len);
            } else {
                ESP_LOGD(TAG, "op=0x%x len=%d", d->op_code, d->data_len);
            }
            break;
        default:
            break;
    }
}

esp_err_t newt_ws_init(const newt_ws_config_t *cfg) {
    if (!cfg || !cfg->endpoint || !cfg->token || !cfg->on_msg) return ESP_ERR_INVALID_ARG;
    if (s_client) return ESP_ERR_INVALID_STATE;

    s_endpoint = strdup(cfg->endpoint);
    s_token    = strdup(cfg->token);
    if (!s_endpoint || !s_token) {
        free(s_endpoint); free(s_token);
        s_endpoint = NULL; s_token = NULL;
        return ESP_ERR_NO_MEM;
    }
    s_cfg.endpoint = s_endpoint;
    s_cfg.token    = s_token;
    s_cfg.on_msg   = cfg->on_msg;
    s_cfg.ctx      = cfg->ctx;

    esp_err_t err = build_ws_url(s_endpoint, s_token, s_url, sizeof(s_url));
    if (err != ESP_OK) goto fail;

    esp_websocket_client_config_t wcfg = {
        .uri                    = s_url,
        .crt_bundle_attach      = esp_crt_bundle_attach,
        .task_prio              = 5,
        .task_stack             = WS_TASK_STACK,
        .buffer_size            = WS_BUFFER_SIZE,
        .network_timeout_ms     = WS_NETWORK_TIMEOUT,
        .reconnect_timeout_ms   = s_backoff_ms[0],
        .ping_interval_sec      = WS_PING_INTERVAL,
        .pingpong_timeout_sec   = WS_PINGPONG_TIMEOUT,
        .enable_close_reconnect = true,
#if !CONFIG_FREERTOS_UNICORE
        .task_core_id_set       = true,
        .task_core_id           = 1,
#endif
    };

    s_queue = xQueueCreate(WS_QUEUE_DEPTH, sizeof(ws_msg_t));
    if (!s_queue) { err = ESP_ERR_NO_MEM; goto fail; }

    s_worker_done = xSemaphoreCreateBinary();
    if (!s_worker_done) { err = ESP_ERR_NO_MEM; goto fail; }
    s_worker_stop_requested = false;

    s_client = esp_websocket_client_init(&wcfg);
    if (!s_client) { err = ESP_FAIL; goto fail; }

    err = esp_websocket_register_events(s_client, WEBSOCKET_EVENT_ANY, ws_event_handler, NULL);
    if (err != ESP_OK) goto fail;

    BaseType_t ok = xTaskCreate(worker_task, "ws_worker", WS_WORKER_STACK, NULL, WS_WORKER_PRIO, &s_worker);
    if (ok != pdPASS) { err = ESP_ERR_NO_MEM; goto fail; }
    return ESP_OK;

fail:
    if (s_client) {
        esp_websocket_client_destroy(s_client);
        s_client = NULL;
    }
    if (s_queue) {
        vQueueDelete(s_queue);
        s_queue = NULL;
    }
    if (s_worker_done) {
        vSemaphoreDelete(s_worker_done);
        s_worker_done = NULL;
    }
    free(s_endpoint);
    free(s_token);
    s_endpoint = NULL;
    s_token = NULL;
    return err;
}

esp_err_t newt_ws_start(void) {
    if (!s_client) return ESP_ERR_INVALID_STATE;
    s_attempt = 0;
    return esp_websocket_client_start(s_client);
}

esp_err_t newt_ws_stop(void) {
    if (!s_client) return ESP_ERR_INVALID_STATE;
    if (esp_websocket_client_is_connected(s_client)) {
        (void)newt_proto_send_disconnecting();
    }
    esp_websocket_client_close(s_client, pdMS_TO_TICKS(1000));
    esp_websocket_client_destroy(s_client);
    s_client = NULL;
    if (s_worker) {
        s_worker_stop_requested = true;
        if (s_queue) {
            ws_msg_t sentinel = { .buf = NULL, .len = 0 };
            (void)xQueueSend(s_queue, &sentinel, 0);
        }
        if (s_worker_done) {
            (void)xSemaphoreTake(s_worker_done, pdMS_TO_TICKS(2000));
        }
        s_worker = NULL;
    }
    if (s_worker_done) {
        vSemaphoreDelete(s_worker_done);
        s_worker_done = NULL;
    }
    if (s_queue) {
        ws_msg_t drain;
        while (xQueueReceive(s_queue, &drain, 0) == pdTRUE) {
            if (drain.buf) free(drain.buf);
        }
        vQueueDelete(s_queue);
        s_queue = NULL;
    }
    free(s_rx_assembly);
    s_rx_assembly = NULL;
    s_rx_assembly_cap = 0;
    s_rx_assembly_len = 0;
    free(s_endpoint);
    free(s_token);
    s_endpoint = NULL;
    s_token = NULL;
    s_worker_stop_requested = false;
    return ESP_OK;
}

bool newt_ws_is_connected(void) {
    if (!s_client) return false;
    return esp_websocket_client_is_connected(s_client);
}

esp_err_t newt_ws_send_envelope(const char *type, const char *data_json) {
    if (!type) return ESP_ERR_INVALID_ARG;
    if (!s_client || !esp_websocket_client_is_connected(s_client)) return ESP_ERR_INVALID_STATE;

    const char *data = (data_json && *data_json) ? data_json : "{}";
    uint64_t ver = newt_proto_get_config_version();

    size_t need = strlen(type) + strlen(data) + 64;
    char *env = malloc(need);
    if (!env) return ESP_ERR_NO_MEM;
    int n = snprintf(env, need, "{\"type\":\"%s\",\"data\":%s,\"configVersion\":%llu}",
                     type, data, (unsigned long long)ver);
    if (n < 0 || (size_t)n >= need) {
        free(env);
        return ESP_ERR_INVALID_SIZE;
    }

    int sent = esp_websocket_client_send_text(s_client, env, n, pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
    free(env);
    if (sent < 0) {
        ESP_LOGW(TAG, "envelope send failed err=%d", sent);
        return ESP_FAIL;
    }
    return ESP_OK;
}
