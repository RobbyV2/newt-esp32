idf_component_register(
    SRCS
        "src/crypto.c"
        "src/wireguard.c"
        "src/wireguardif.c"
        "src/wireguard-platform.c"
        "src/esp_wireguard.c"
        "src/crypto/refc/blake2s.c"
        "src/crypto/refc/chacha20.c"
        "src/crypto/refc/chacha20poly1305.c"
        "src/crypto/refc/poly1305-donna.c"
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
    REQUIRES
        esp_netif
        lwip
        mbedtls
    PRIV_REQUIRES
        esphome__libsodium
)

# IDF 6.0 / GCC 15 strict warns on libsodium x25519 unused-result; vendored fork can't be patched
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=unused-result -Wno-unused-result)
