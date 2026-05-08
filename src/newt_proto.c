#include "newt_proto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"

#include "cJSON.h"
#include "mbedtls/base64.h"

#include "newt_ws.h"

static const char *TAG = "PROTO";

static newt_proto_callbacks_t s_cb;
static uint64_t                s_config_version;
/* single-writer (supervisor) single-reader (worker on core 1); request-reply ordering enforces happens-before */
static char                    s_inflight_chain_register[17];
static char                    s_inflight_chain_ping_request[17];
static int                     s_chosen_exit_node_id = -1;

static void chainId_new(char out[17])
{
    uint8_t bytes[8];
    for (size_t i = 0; i < sizeof(bytes); i += 4) {
        uint32_t r = esp_random();
        bytes[i + 0] = (uint8_t)(r & 0xFF);
        bytes[i + 1] = (uint8_t)((r >> 8) & 0xFF);
        bytes[i + 2] = (uint8_t)((r >> 16) & 0xFF);
        bytes[i + 3] = (uint8_t)((r >> 24) & 0xFF);
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        out[i * 2 + 0] = hex[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    out[16] = '\0';
}

esp_err_t newt_proto_init(const newt_proto_callbacks_t *cb)
{
    if (cb == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(&s_cb, cb, sizeof(s_cb));
    s_config_version = 0;
    memset(s_inflight_chain_register, 0, sizeof(s_inflight_chain_register));
    memset(s_inflight_chain_ping_request, 0, sizeof(s_inflight_chain_ping_request));
    s_chosen_exit_node_id = -1;
    return ESP_OK;
}

uint64_t newt_proto_get_config_version(void)
{
    return s_config_version;
}

static esp_err_t handle_wg_connect(const char *data_json)
{
    cJSON *root = cJSON_Parse(data_json);
    if (root == NULL) {
        ESP_LOGW(TAG, "wg/connect: parse failed");
        return ESP_FAIL;
    }
    esp_err_t ret = ESP_FAIL;

    bool chain_matched = false;
    const cJSON *jchain = cJSON_GetObjectItemCaseSensitive(root, "chainId");
    if (cJSON_IsString(jchain) && jchain->valuestring != NULL && jchain->valuestring[0] != '\0') {
        if (s_inflight_chain_register[0] != '\0' &&
            strcmp(jchain->valuestring, s_inflight_chain_register) != 0) {
            ESP_LOGI(TAG, "wg/connect chainId mismatch got=%s want=%s, dropping", jchain->valuestring, s_inflight_chain_register);
            ret = ESP_OK;
            goto out;
        }
        chain_matched = true;
    } else {
        ESP_LOGW(TAG, "wg/connect: missing chainId, proceeding without consuming inflight");
    }

    const cJSON *jendpoint = cJSON_GetObjectItemCaseSensitive(root, "endpoint");
    const cJSON *jpubkey   = cJSON_GetObjectItemCaseSensitive(root, "publicKey");
    const cJSON *jserverip = cJSON_GetObjectItemCaseSensitive(root, "serverIP");
    const cJSON *jtunnelip = cJSON_GetObjectItemCaseSensitive(root, "tunnelIP");
    if (!cJSON_IsString(jendpoint) || !cJSON_IsString(jpubkey) ||
        !cJSON_IsString(jserverip) || !cJSON_IsString(jtunnelip)) {
        ESP_LOGW(TAG, "wg/connect: missing required fields");
        goto out;
    }

    const char *endpoint_str = jendpoint->valuestring;
    const char *host_start = endpoint_str;
    size_t host_len = 0;
    const char *port_str = NULL;
    if (endpoint_str[0] == '[') {
        const char *rb = strchr(endpoint_str, ']');
        if (rb == NULL || rb[1] != ':') {
            ESP_LOGW(TAG, "wg/connect: malformed [IPv6]:port endpoint");
            goto out;
        }
        host_start = endpoint_str + 1;
        host_len = (size_t)(rb - host_start);
        port_str = rb + 2;
    } else {
        const char *colon = strrchr(endpoint_str, ':');
        if (colon == NULL) {
            ESP_LOGW(TAG, "wg/connect: endpoint missing port");
            goto out;
        }
        host_len = (size_t)(colon - endpoint_str);
        port_str = colon + 1;
    }
    if (host_len == 0 || host_len >= NEWT_PROTO_ENDPOINT_MAX) {
        ESP_LOGW(TAG, "wg/connect: endpoint host too long");
        goto out;
    }
    long port = strtol(port_str, NULL, 10);
    if (port <= 0 || port > 65535) {
        ESP_LOGW(TAG, "wg/connect: invalid port");
        goto out;
    }

    newt_proto_wg_connect_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.endpoint, host_start, host_len);
    cfg.endpoint[host_len] = '\0';
    cfg.endpoint_port = (uint16_t)port;

    size_t pubkey_len = 0;
    int b64ret = mbedtls_base64_decode(cfg.server_pubkey, NEWT_WG_KEY_LEN,
                                       &pubkey_len,
                                       (const unsigned char *)jpubkey->valuestring,
                                       strlen(jpubkey->valuestring));
    if (b64ret != 0 || pubkey_len != NEWT_WG_KEY_LEN) {
        ESP_LOGW(TAG, "wg/connect: pubkey decode failed");
        goto out;
    }

    size_t srv_len = strlen(jserverip->valuestring);
    size_t tun_len = strlen(jtunnelip->valuestring);
    if (srv_len >= sizeof(cfg.server_ip) || tun_len >= sizeof(cfg.tunnel_ip)) {
        ESP_LOGW(TAG, "wg/connect: ip string too long");
        goto out;
    }
    memcpy(cfg.server_ip, jserverip->valuestring, srv_len + 1);
    memcpy(cfg.tunnel_ip, jtunnelip->valuestring, tun_len + 1);

    ESP_LOGI(TAG, "received newt/wg/connect tunnelIP=%s", cfg.tunnel_ip);

    if (s_cb.on_wg_connect != NULL) {
        s_cb.on_wg_connect(&cfg, s_cb.ctx);
    }
    if (chain_matched) {
        s_inflight_chain_register[0] = '\0';
    }
    ret = ESP_OK;

out:
    cJSON_Delete(root);
    return ret;
}

static esp_err_t handle_exit_nodes(const char *data_json)
{
    cJSON *root = cJSON_Parse(data_json);
    if (root == NULL) {
        ESP_LOGW(TAG, "ping/exitNodes: parse failed");
        return ESP_FAIL;
    }
    const cJSON *jchain = cJSON_GetObjectItemCaseSensitive(root, "chainId");
    if (cJSON_IsString(jchain) && jchain->valuestring != NULL && jchain->valuestring[0] != '\0') {
        if (s_inflight_chain_ping_request[0] != '\0' &&
            strcmp(jchain->valuestring, s_inflight_chain_ping_request) != 0) {
            ESP_LOGI(TAG, "ping/exitNodes chainId mismatch got=%s want=%s, dropping", jchain->valuestring, s_inflight_chain_ping_request);
            cJSON_Delete(root);
            return ESP_OK;
        }
        s_inflight_chain_ping_request[0] = '\0';
    } else {
        ESP_LOGW(TAG, "ping/exitNodes: missing chainId, proceeding without consuming inflight");
    }

    const cJSON *jnodes = cJSON_GetObjectItemCaseSensitive(root, "exitNodes");
    if (cJSON_IsArray(jnodes) && cJSON_GetArraySize(jnodes) > 0) {
        const cJSON *jfirst = cJSON_GetArrayItem(jnodes, 0);
        const cJSON *jid = cJSON_GetObjectItemCaseSensitive(jfirst, "exitNodeId");
        if (cJSON_IsNumber(jid)) {
            s_chosen_exit_node_id = jid->valueint;
            ESP_LOGI(TAG, "ping/exitNodes: chose exitNodeId=%d", s_chosen_exit_node_id);
        } else {
            ESP_LOGW(TAG, "ping/exitNodes: first node missing exitNodeId");
        }
    } else if (cJSON_IsArray(jnodes)) {
        ESP_LOGE(TAG, "[PROTO] no exit nodes available; check Pangolin site config (site has zero reachable exit nodes)");
    } else {
        ESP_LOGW(TAG, "ping/exitNodes: missing exitNodes array");
    }
    cJSON_Delete(root);

    if (s_cb.on_exit_nodes != NULL) {
        s_cb.on_exit_nodes(s_cb.ctx);
    }
    return ESP_OK;
}

esp_err_t newt_proto_handle_message(const char *type,
                                    const char *data_json,
                                    size_t data_len,
                                    uint64_t config_version)
{
    (void)data_len;
    if (type == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGD(TAG, "handle type=%s data=%.500s", type, data_json ? data_json : "(null)");
    if (config_version > s_config_version) {
        s_config_version = config_version;
    }

    if (strcmp(type, "newt/wg/connect") == 0) {
        if (data_json == NULL) {
            return ESP_ERR_INVALID_ARG;
        }
        return handle_wg_connect(data_json);
    }
    if (strcmp(type, "newt/wg/reconnect") == 0) {
        ESP_LOGI(TAG, "wg reconnect requested");
        if (s_cb.on_wg_reconnect != NULL) {
            s_cb.on_wg_reconnect(s_cb.ctx);
        }
        return ESP_OK;
    }
    if (strcmp(type, "newt/wg/terminate") == 0) {
        ESP_LOGI(TAG, "wg terminate requested");
        if (s_cb.on_wg_terminate != NULL) {
            s_cb.on_wg_terminate(s_cb.ctx);
        }
        return ESP_OK;
    }
    if (strcmp(type, "newt/ping/exitNodes") == 0) {
        if (data_json == NULL) {
            return ESP_ERR_INVALID_ARG;
        }
        return handle_exit_nodes(data_json);
    }
    if (strcmp(type, "newt/sync") == 0) {
        return ESP_OK;
    }
    if (strcmp(type, "pong") == 0) {
        return ESP_OK;
    }
    ESP_LOGD(TAG, "unhandled type=%s", type);
    return ESP_OK;
}

esp_err_t newt_proto_send_ping_request(void)
{
    chainId_new(s_inflight_chain_ping_request);
    char buf[96];
    int n = snprintf(buf, sizeof(buf),
                     "{\"noCloud\":false,\"chainId\":\"%s\"}",
                     s_inflight_chain_ping_request);
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        return ESP_FAIL;
    }
    return newt_ws_send_envelope("newt/ping/request", buf);
}

esp_err_t newt_proto_send_register(const uint8_t local_pubkey[NEWT_WG_KEY_LEN])
{
    if (local_pubkey == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    unsigned char b64[64];
    size_t b64_len = 0;
    int rc = mbedtls_base64_encode(b64, sizeof(b64), &b64_len,
                                   local_pubkey, NEWT_WG_KEY_LEN);
    if (rc != 0) {
        return ESP_FAIL;
    }
    b64[b64_len] = '\0';

    chainId_new(s_inflight_chain_register);
    ESP_LOGI(TAG, "register chainId=%s exit_node_id=%d", s_inflight_chain_register, s_chosen_exit_node_id);

    char buf[512];
    int n;
    if (s_chosen_exit_node_id >= 0) {
        n = snprintf(buf, sizeof(buf),
                     "{\"publicKey\":\"%s\",\"pingResults\":[{\"exitNodeId\":%d,\"latencyMs\":1,\"weight\":1,\"exitNodeName\":\"\",\"endpoint\":\"\",\"wasPreviouslyConnected\":false}],\"newtVersion\":\"\",\"chainId\":\"%s\"}",
                     (const char *)b64, s_chosen_exit_node_id, s_inflight_chain_register);
    } else {
        ESP_LOGW(TAG, "register: no exit node id known, sending empty pingResults");
        n = snprintf(buf, sizeof(buf),
                     "{\"publicKey\":\"%s\",\"pingResults\":[],\"newtVersion\":\"\",\"chainId\":\"%s\"}",
                     (const char *)b64, s_inflight_chain_register);
    }
    if (n < 0) {
        ESP_LOGE(TAG, "register: snprintf encode error");
        return ESP_FAIL;
    }
    if ((size_t)n >= sizeof(buf)) {
        ESP_LOGE(TAG, "register: payload truncated need=%d cap=%u", n, (unsigned)sizeof(buf));
        return ESP_FAIL;
    }
    esp_err_t err = newt_ws_send_envelope("newt/wg/register", buf);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "register sent pubkey=%02x%02x...",
                 local_pubkey[0], local_pubkey[1]);
    }
    return err;
}

esp_err_t newt_proto_send_ping(void)
{
    return newt_ws_send_envelope("newt/ping", "{}");
}

esp_err_t newt_proto_send_disconnecting(void)
{
    return newt_ws_send_envelope("newt/disconnecting", "{}");
}
