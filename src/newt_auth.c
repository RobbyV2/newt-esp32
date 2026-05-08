#include "newt_auth.h"

#include <string.h>
#include <stdlib.h>

#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "cJSON.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "AUTH";

#define AUTH_TIMEOUT_MS 10000
#define RESP_INIT_CAP   1024
#define RESP_MAX_CAP    8192

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    bool   oom;
} http_resp_t;

static esp_err_t resp_append(http_resp_t *r, const char *data, size_t n) {
    size_t need = r->len + n + 1;
    if (need > RESP_MAX_CAP) {
        r->oom = true;
        return ESP_ERR_NO_MEM;
    }
    if (need > r->cap) {
        size_t nc = r->cap ? r->cap : RESP_INIT_CAP;
        while (nc < need) nc *= 2;
        if (nc > RESP_MAX_CAP) nc = RESP_MAX_CAP;
        char *nb = realloc(r->buf, nc);
        if (!nb) {
            r->oom = true;
            return ESP_ERR_NO_MEM;
        }
        r->buf = nb;
        r->cap = nc;
    }
    memcpy(r->buf + r->len, data, n);
    r->len += n;
    r->buf[r->len] = '\0';
    return ESP_OK;
}

static esp_err_t http_event_cb(esp_http_client_event_t *evt) {
    http_resp_t *r = (http_resp_t *)evt->user_data;
    if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data && evt->data_len > 0 && r) {
        resp_append(r, (const char *)evt->data, (size_t)evt->data_len);
    }
    return ESP_OK;
}

static esp_err_t do_post(const char *url, const char *body, http_resp_t *r, int *out_status) {
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = AUTH_TIMEOUT_MS,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = http_event_cb,
        .user_data = r,
    };
    esp_http_client_handle_t cli = esp_http_client_init(&cfg);
    if (!cli) {
        ESP_LOGE(TAG, "client init failed");
        return ESP_FAIL;
    }
    esp_http_client_set_header(cli, "Content-Type", "application/json");
    esp_http_client_set_header(cli, "X-CSRF-Token", "x-csrf-protection");
    esp_http_client_set_post_field(cli, body, (int)strlen(body));

    esp_err_t err = esp_http_client_perform(cli);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tls error or clock skew? %s", esp_err_to_name(err));
        esp_http_client_cleanup(cli);
        return err;
    }
    *out_status = esp_http_client_get_status_code(cli);
    esp_http_client_cleanup(cli);
    if (r->oom) {
        ESP_LOGE(TAG, "response too large");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static esp_err_t copy_field(const cJSON *data, const char *key,
                            char *out, size_t out_size, size_t *out_len) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(data, key);
    if (!cJSON_IsString(v) || !v->valuestring) return ESP_ERR_INVALID_RESPONSE;
    size_t n = strlen(v->valuestring);
    if (n + 1 > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, v->valuestring, n + 1);
    if (out_len) *out_len = n;
    return ESP_OK;
}

static char *build_url(const char *endpoint, const char *path) {
    size_t elen = strlen(endpoint);
    while (elen > 0 && endpoint[elen - 1] == '/') elen--;
    size_t plen = strlen(path);
    char *u = malloc(elen + plen + 1);
    if (!u) return NULL;
    memcpy(u, endpoint, elen);
    memcpy(u + elen, path, plen + 1);
    return u;
}

esp_err_t newt_auth_get_token(const char *endpoint,
                              const char *newt_id,
                              const char *newt_secret,
                              char *out_token,
                              size_t out_token_size,
                              size_t *out_token_len) {
    if (!endpoint || !newt_id || !newt_secret || !out_token || out_token_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *req = cJSON_CreateObject();
    if (!req) return ESP_ERR_NO_MEM;
    cJSON_AddStringToObject(req, "newtId", newt_id);
    cJSON_AddStringToObject(req, "secret", newt_secret);
    char *body = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body) return ESP_ERR_NO_MEM;

    char *url = build_url(endpoint, "/api/v1/auth/newt/get-token");
    if (!url) {
        mbedtls_platform_zeroize(body, strlen(body));
        free(body);
        return ESP_ERR_NO_MEM;
    }

    http_resp_t r = {0};
    int status = 0;
    esp_err_t err = do_post(url, body, &r, &status);
    free(url);
    mbedtls_platform_zeroize(body, strlen(body));
    free(body);
    if (err != ESP_OK) {
        if (r.buf) { mbedtls_platform_zeroize(r.buf, r.len); free(r.buf); }
        return err;
    }

    ESP_LOGI(TAG, "http status=%d", status);
    if (status != 200) {
        if (r.buf) { mbedtls_platform_zeroize(r.buf, r.len); free(r.buf); }
        return (status == 401 || status == 403) ? ESP_ERR_NOT_ALLOWED : ESP_FAIL;
    }

    cJSON *root = cJSON_ParseWithLength(r.buf, r.len);
    mbedtls_platform_zeroize(r.buf, r.len);
    free(r.buf);
    if (!root) {
        ESP_LOGE(TAG, "json parse failed");
        return ESP_ERR_INVALID_RESPONSE;
    }
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (!cJSON_IsObject(data)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_RESPONSE;
    }
    size_t tlen = 0;
    err = copy_field(data, "token", out_token, out_token_size, &tlen);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "token field missing or buffer too small");
        return err;
    }
    if (out_token_len) *out_token_len = tlen;
    ESP_LOGI(TAG, "token acquired len=%u", (unsigned)tlen);
    return ESP_OK;
}

esp_err_t newt_auth_register_with_provisioning_key(const char *endpoint,
                                                   const char *provisioning_key,
                                                   const char *name,
                                                   char *out_id,
                                                   size_t out_id_size,
                                                   size_t *out_id_len,
                                                   char *out_secret,
                                                   size_t out_secret_size,
                                                   size_t *out_secret_len) {
    if (!endpoint || !provisioning_key || !out_id || out_id_size == 0 ||
        !out_secret || out_secret_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *req = cJSON_CreateObject();
    if (!req) return ESP_ERR_NO_MEM;
    cJSON_AddStringToObject(req, "provisioningKey", provisioning_key);
    if (name && name[0]) cJSON_AddStringToObject(req, "name", name);
    char *body = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body) return ESP_ERR_NO_MEM;

    char *url = build_url(endpoint, "/api/v1/auth/newt/register");
    if (!url) {
        mbedtls_platform_zeroize(body, strlen(body));
        free(body);
        return ESP_ERR_NO_MEM;
    }

    http_resp_t r = {0};
    int status = 0;
    esp_err_t err = do_post(url, body, &r, &status);
    free(url);
    mbedtls_platform_zeroize(body, strlen(body));
    free(body);
    if (err != ESP_OK) {
        if (r.buf) { mbedtls_platform_zeroize(r.buf, r.len); free(r.buf); }
        return err;
    }

    ESP_LOGI(TAG, "register http status=%d", status);
    if (status != 201 && status != 200) {
        if (r.buf) { mbedtls_platform_zeroize(r.buf, r.len); free(r.buf); }
        return (status == 401 || status == 403) ? ESP_ERR_NOT_ALLOWED : ESP_FAIL;
    }

    cJSON *root = cJSON_ParseWithLength(r.buf, r.len);
    mbedtls_platform_zeroize(r.buf, r.len);
    free(r.buf);
    if (!root) {
        ESP_LOGE(TAG, "json parse failed");
        return ESP_ERR_INVALID_RESPONSE;
    }
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (!cJSON_IsObject(data)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_RESPONSE;
    }
    size_t ilen = 0, slen = 0;
    err = copy_field(data, "newtId", out_id, out_id_size, &ilen);
    if (err == ESP_OK) err = copy_field(data, "secret", out_secret, out_secret_size, &slen);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "register field missing or buffer too small");
        return err;
    }
    if (out_id_len) *out_id_len = ilen;
    if (out_secret_len) *out_secret_len = slen;
    ESP_LOGI(TAG, "registered newt_id_len=%u secret_len=%u", (unsigned)ilen, (unsigned)slen);
    return ESP_OK;
}
