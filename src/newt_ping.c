#include "newt_ping.h"

#include <string.h>

#include "ping/ping_sock.h"
#include "lwip/inet.h"
#include "esp_log.h"

static esp_ping_handle_t s_ping;
static newt_ping_config_t s_cfg;
static const char *TAG = "PING";

#define PING_TASK_STACK 4096
#define PING_TASK_PRIO  4

static void on_ping_success(esp_ping_handle_t hdl, void *args)
{
    uint32_t elapsed_ms;
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_ms, sizeof(elapsed_ms));
    ip_addr_t addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &addr, sizeof(addr));
    esp_ip4_addr_t reply = { .addr = addr.u_addr.ip4.addr };
    ESP_LOGI(TAG, "ping reply from " IPSTR " elapsed=%lums", IP2STR(&reply), (unsigned long)elapsed_ms);
    if (s_cfg.on_reply) {
        s_cfg.on_reply(&reply, elapsed_ms, s_cfg.ctx);
    }
}

static void on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    ESP_LOGD(TAG, "ping timeout");
}

static void on_ping_end(esp_ping_handle_t hdl, void *args)
{
    ESP_LOGD(TAG, "ping ended");
}

esp_err_t newt_ping_init(const newt_ping_config_t *cfg)
{
    if (!cfg) {
        return ESP_ERR_INVALID_ARG;
    }
    s_cfg = *cfg;

    esp_ping_config_t ping_cfg = ESP_PING_DEFAULT_CONFIG();
    ping_cfg.target_addr.u_addr.ip4.addr = cfg->target.addr;
    ping_cfg.target_addr.type = IPADDR_TYPE_V4;
    ping_cfg.count = cfg->max_attempts;
    ping_cfg.interval_ms = cfg->interval_ms;
    ping_cfg.timeout_ms = cfg->timeout_ms;
    ping_cfg.task_stack_size = PING_TASK_STACK;
    ping_cfg.task_prio = PING_TASK_PRIO;

    esp_ping_callbacks_t cbs = {
        .on_ping_success = on_ping_success,
        .on_ping_timeout = on_ping_timeout,
        .on_ping_end = on_ping_end,
        .cb_args = NULL,
    };

    esp_err_t err = esp_ping_new_session(&ping_cfg, &cbs, &s_ping);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ping new_session failed: %d", err);
        return err;
    }

    ESP_LOGI(TAG, "ping init target=" IPSTR, IP2STR(&cfg->target));
    return ESP_OK;
}

esp_err_t newt_ping_start(void)
{
    if (!s_ping) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_ping_start(s_ping);
}

esp_err_t newt_ping_stop(void)
{
    if (!s_ping) {
        return ESP_OK;
    }
    esp_ping_stop(s_ping);
    esp_ping_delete_session(s_ping);
    s_ping = NULL;
    return ESP_OK;
}
