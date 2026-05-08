#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_chip_info.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "newt.h"
#include "newt_secrets.h"

#define WIFI_GOT_IP_BIT BIT0

#define HEAP_PROBE_STACK     2048
#define WIFI_DC_TEST_STACK   2048

static const char *TAG = "BASIC";
static EventGroupHandle_t s_wifi_evt;
static httpd_handle_t s_httpd;

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW("WIFI", "lost, reconnecting");
        xEventGroupClearBits(s_wifi_evt, WIFI_GOT_IP_BIT);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ip = (ip_event_got_ip_t *)data;
        ESP_LOGI("WIFI", "got ip " IPSTR, IP2STR(&ip->ip_info.ip));
        xEventGroupSetBits(s_wifi_evt, WIFI_GOT_IP_BIT);
    }
}

static esp_err_t hello_handler(httpd_req_t *req) {
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const char *chip_name = "unknown";
    switch (chip.model) {
        case CHIP_ESP32:   chip_name = "esp32";   break;
        case CHIP_ESP32S2: chip_name = "esp32s2"; break;
        case CHIP_ESP32S3: chip_name = "esp32s3"; break;
        case CHIP_ESP32C3: chip_name = "esp32c3"; break;
        case CHIP_ESP32C6: chip_name = "esp32c6"; break;
        default: break;
    }
    int64_t uptime_us = esp_timer_get_time();
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"chip\":\"%s\",\"uptime\":%lld}", chip_name, (long long)(uptime_us / 1000000));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static void heap_probe_task(void *arg) {
    (void)arg;
    for (;;) {
        ESP_LOGI("HEAP", "free=%u min_free=%u",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
        vTaskDelay(pdMS_TO_TICKS(60000));
    }
}

#ifdef NEWT_TEST_WIFI_DISCONNECT
static void wifi_disconnect_test_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(90000));
    ESP_LOGI("TEST", "wifi disconnect triggered");
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(20000));
    ESP_LOGI("TEST", "wifi reconnect triggered");
    esp_wifi_connect();
    vTaskDelete(NULL);
}
#endif

static void newt_evt_cb(newt_event_t evt, void *data) {
    (void)data;
    if (evt == NEWT_EVT_ONLINE) {
        static bool started = false;
        if (!started) {
            started = true;
            xTaskCreate(heap_probe_task, "heap_probe", HEAP_PROBE_STACK, NULL, 1, NULL);
#ifdef NEWT_TEST_WIFI_DISCONNECT
            xTaskCreate(wifi_disconnect_test_task, "wifi_dc_test", WIFI_DC_TEST_STACK, NULL, 1, NULL);
#endif
        }
        httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
        // pangolin reverse-proxy targets this listen port; see site's targets.tcp
        cfg.server_port = 59248;
        if (httpd_start(&s_httpd, &cfg) == ESP_OK) {
            httpd_uri_t uri = {
                .uri = "/",
                .method = HTTP_GET,
                .handler = hello_handler,
                .user_ctx = NULL,
            };
            httpd_register_uri_handler(s_httpd, &uri);
            ESP_LOGI(TAG, "demo http server up on 0.0.0.0:59248");
        }
    }
}

void app_main(void) {
    esp_err_t r = nvs_flash_init();
    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    s_wifi_evt = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_init_config_t wifi_init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init));
    wifi_config_t wifi_cfg = { 0 };
    strncpy((char *)wifi_cfg.sta.ssid, NEWT_WIFI_SSID, sizeof(wifi_cfg.sta.ssid));
    strncpy((char *)wifi_cfg.sta.password, NEWT_WIFI_PASS, sizeof(wifi_cfg.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "waiting for WiFi");
    xEventGroupWaitBits(s_wifi_evt, WIFI_GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    ESP_LOGI(TAG, "syncing SNTP");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();
    time_t now = 0;
    int wait = 0;
    while (now < 1700000000 && wait < 60) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        time(&now);
        wait++;
    }
    if (now < 1700000000) {
        ESP_LOGE("TIME", "sntp failed; aborting");
        esp_restart();
    }
    ESP_LOGI("TIME", "synced epoch=%lld", (long long)now);

    newt_config_t cfg = {
        .endpoint = NEWT_NEWT_ENDPOINT,
        .newt_id = NEWT_NEWT_ID,
        .newt_secret = NEWT_NEWT_SECRET,
        .on_event = newt_evt_cb,
    };
    ESP_ERROR_CHECK(newt_init(&cfg));
    ESP_ERROR_CHECK(newt_start());
    ESP_LOGI(TAG, "newt started");
}
