# newt-esp32

ESP-IDF library that registers an ESP32 as a Pangolin site over WireGuard. Mirrors the behavior of the Go [fosrl/newt](https://github.com/fosrl/newt) client. Transport-agnostic; the consumer handles WiFi (or Ethernet, cellular) bring-up and SNTP time sync, then passes credentials to `newt_init()`. The library handles auth, the WSS control channel, the WireGuard handshake, and the wake-ping.

Targets: esp32, esp32s2, esp32s3, esp32c3, esp32c6.

## Prerequisites

A working ESP-IDF or PlatformIO toolchain. If neither is installed yet, follow [Espressif's ESP-IDF Get Started guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) or the [PlatformIO + Espressif 32 platform docs](https://docs.platformio.org/en/latest/platforms/espressif32.html).

Tested against ESP-IDF 6.0 with PlatformIO `platform = espressif32@^7.0.0`. The library declares `idf: ">=5.1"` and is expected to build under recent IDF 5.x as well, but the primary development target is IDF 6.0.

## Install

ESP-IDF Component Manager, in `idf_component.yml`:

```yaml
dependencies:
  robby/newt-esp32: "^0.1.0"
```

PlatformIO, in `platformio.ini`:

```ini
lib_deps =
    robby/newt-esp32@^0.1.0
```

## Setup

The library does not ship its WireGuard backend, requires several sdkconfig keys on IDF 5.x and 6.x, and assumes the caller has initialized NVS and synced wall-clock time before `newt_init()` runs.

### 1. Vendor the droscy esp_wireguard fork

The library declares `esp_wireguard` in `PRIV_REQUIRES` but does not bundle it. The registry build (`trombik/esp_wireguard`) fails on IDF 6.0 / GCC 15 strict warnings. The droscy fork swaps x25519 to libsodium and patches the unterminated string init that breaks under `-Werror=unterminated-string-initialization`. Vendor the droscy fork at `<your-project>/components/esp_wireguard/`.

Copy the prebuilt vendored component from `examples/basic/components/esp_wireguard/` in this repo, or clone https://github.com/droscy/esp_wireguard into `components/esp_wireguard/` and append to its `CMakeLists.txt`:

```cmake
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=unused-result -Wno-unused-result)
```

### 2. sdkconfig keys

Add to `sdkconfig.defaults`:

```
CONFIG_LWIP_PPP_SUPPORT=y                       # WG netif callback workaround on IDF 6
CONFIG_LWIP_SO_REUSE=y                          # HTTP server rebind tolerance
CONFIG_WS_TRANSPORT=y                           # esp_websocket_client TLS
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y             # Pangolin TLS chain
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y
```

### 3. Build flag

Add to `platformio.ini` (or equivalent IDF build flag):

```ini
build_flags = -DCONFIG_WIREGUARD_MAX_SRC_IPS=4    # Allow adding server IP as second allowed_ip
```

The droscy default is 1, which leaves no room for the library to register the server IP alongside the tunnel IP.

### 4. Runtime preconditions

The caller MUST initialize NVS (`nvs_flash_init()`) AND have time-of-day synced via SNTP (epoch > 1700000000) BEFORE calling `newt_init()`. The library does not bring up either. WireGuard handshakes embed TAI64N timestamps and the responder rejects monotonically-decreasing timestamps as replays, so a device that handshakes once at the 1970 epoch cannot recover.

## Usage

After WiFi is up and the system clock is SNTP-synced:

```c
#include "newt.h"

newt_config_t cfg = {
    .endpoint    = "https://pangolin.example.com",
    .newt_id     = "your-newt-id",
    .newt_secret = "your-newt-secret",
};
ESP_ERROR_CHECK(newt_init(&cfg));
ESP_ERROR_CHECK(newt_start());
```

Obtain `newt_id` and `newt_secret` from the Pangolin admin UI (Sites → New Site); Pangolin issues the credential pair on creation. To bootstrap programmatically without a pre-issued pair, also `#include "newt_auth.h"` and call `newt_auth_register_with_provisioning_key()` to exchange a provisioning key for a credential pair.

For your own consumer project, pass values into `newt_config_t` however you prefer (hardcoded, NVS, secure storage, etc.). The library only reads the pointers at `newt_init()` time and copies them internally.

A reference consumer with WiFi STA bring-up, SNTP sync, NVS init, and an HTTP server bound to the WireGuard tunnel listen port is in [`examples/basic/`](examples/basic/).

### Running the example

The example uses a small codegen step so credentials never live in source control:

1. Copy `examples/basic/.env.example` to `examples/basic/.env`.
2. Fill in `NEWT_ID`, `NEWT_SECRET`, `NEWT_ENDPOINT`, `WIFI_SSID`, `WIFI_PASS`.
3. Build with PlatformIO or `idf.py`. Pure CMake reads `examples/basic/.env` at IDF configure time and generates `newt_secrets.h` inside the build directory (e.g. `.pio/build/<env>/esp-idf/main/newt_secrets.h`). `main.c` includes that header and references the contents as `NEWT_<KEY>` macros.

The build directory is added to the main component's include path, so the header is picked up without polluting the source tree. CMake registers `.env` via `CMAKE_CONFIGURE_DEPENDS`, so editing it triggers a re-configure on the next build automatically.

### Port-binding pattern

The example binds its HTTP server to the Pangolin-advertised tunnel listen port (varies per site config; see `examples/basic/main/main.c`, where the port is hardcoded to match the site's `targets.tcp` entry). For a different reverse-proxy strategy, read the Pangolin site's `targets.tcp` and bind accordingly, or implement an internal TCP proxy that fans incoming tunnel traffic to the local port the application listens on.

## Troubleshooting

**`Failed to resolve component 'newt-esp32'`** when building the example: the cloned repository directory must be named exactly `newt-esp32`. The example's `examples/basic/main/idf_component.yml` uses `override_path: "../../../"` to pull the local library, and ESP-IDF Component Manager validates that the resolved component matches the dependency name. Renaming the directory or extracting a GitHub ZIP (which appends a hash suffix) breaks resolution. Either rename the directory back to `newt-esp32`, or change the dependency key in `idf_component.yml` to match the actual directory name.

**`auth failed err=ESP_ERR_HTTP_*`** from the supervisor task: confirm `newt_id`, `newt_secret`, and `endpoint` are correct, the endpoint URL includes the scheme (`https://`), and that SNTP has set wall-clock time above the 1700000000 epoch threshold before `newt_init()` is called. The library logs the underlying error code via `esp_err_to_name()` for further triage.

**`wg handshake timeout`**: the auth and websocket steps succeeded but the WireGuard handshake never completed. Verify the device can reach the Pangolin server's UDP listen port (logged in the timeout message) and that no upstream firewall is dropping outbound UDP.

## License

MIT for this library. The vendored droscy `esp_wireguard` fork under `examples/basic/components/esp_wireguard/` is BSD-3-Clause; see its bundled `LICENSE` file. Only the example consumer carries that dependency; the published library archive excludes the `examples/` tree.
