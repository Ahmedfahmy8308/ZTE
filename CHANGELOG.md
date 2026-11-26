# Changelog

All notable changes to the **ZTE Unified Management Toolkit (ZXHN H188A & H168N V3.1)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-11-26

### Added
- **Multi-Router Architecture (`H188a_toolkit` & `H168n_toolkit`):**
  - Reorganized `app/` into symmetric Rust + Python + HTML toolkits for both **ZXHN H188A** and **ZXHN H168N V3.1**.
  - Added dedicated per-router launchers: `Run_H188a.bat` (`http://127.0.0.1:8080`, `--mode h188a`) and `Run_H168n.bat` (`http://127.0.0.1:8082`, `--mode h168n` + TLS 1.0 proxy on `8081`).
  - Added per-router `config.example.ini` templates, a root MIT `LICENSE` file, and updated `.gitignore` for Rust `target/`, `config.ini`, and extracted firmware artifacts.
- **Native Rust Tooling (`zcu-rs`, `h168n-cli`, `h188a-cli`):**
  - Built `zcu-rs` for `config.bin` decoding and encoding across Type-0 (ZLIB), Type-2 (AES-128-ECB), and Type-3/4 (AES-256-CBC + SHA-256) with automatic key derivation from signatures, serial numbers, and MAC addresses.
  - Built `h168n-cli` with automatic network adapter discovery (`detect`), legacy `TLSv1` (`@SECLEVEL=0`) reverse proxy (`proxy` with `Content-Length` fast framing), Wi-Fi management (`set-wifi`), and `zcu-decode` / `zcu-encode`.
  - Built `h188a-cli` with binary firmware inspection (`fw-inspect`), reachability checks (`ping`), and Type-4 `config.bin` support.
- **Dual-Mode Web Dashboard (`web_app.py`):**
  - Added isolated `--mode h188a` and `--mode h168n` dashboards with mode-aware firmware inspection (`POST /api/firmware/inspect`, `/api/firmware/upload`), adapter selector, SHA-256 login (`/api/h168n/login`), Wi-Fi/Access Point configuration, and browser-based `config.bin` decode/encode.
- **Symmetric Firmware Workspace (`Firmware/`):**
  - Split `Firmware/` into `Firmware/H188a/` and `Firmware/H168n/` (`H168N_V3.1.0EG1T11_TE.bin`), each with `rootfs.squashfs` and `extracted_sample/`.

### Fixed
- **Dual-Router IP Conflict (`192.168.1.1`):** Updated `H188a_toolkit/zte_toolkit/client.py` with `_BoundHTTPSHandler` to auto-detect and bind to the Wi-Fi interface (`H188A`) instead of routing to the Ethernet-connected `H168N`.
- **Legacy TLS Proxy Latency:** Updated `h168n-cli` proxy response reader to terminate cleanly once `Content-Length` bytes are received instead of waiting for router socket EOF timeouts.
- **H168N Mode Firmware Inspection:** Routed both `GET` and `POST` `/api/firmware/inspect` and `/api/firmware/upload` to `inspect_h168n_firmware` and updated UI labels when running in `--mode h168n`.

### Removed
- Removed legacy `Run.bat` in favor of dedicated `Run_H188a.bat` and `Run_H168n.bat` launchers.

---

## [2.2.0] - 2026-11-13

### Added
- **Full Dual-Localization (Arabic / English):**
  - Integrated one-click language switcher (`[ English ]` / `[ العربية ]`) in the top navigation header.
  - Real-time DOM attribute translation (`data-i18n`, `data-i18n-val`, `data-i18n-placeholder`) with dynamic document direction switching (`dir="rtl"` for Arabic, `dir="ltr"` for English).
  - Persistent language selection saved via browser `localStorage`.
- **Firmware Management & Upgrade Suite:**
  - Added dedicated navigation tab (`#panel_firmware`) with 1-to-1 official carrier styling.
  - **Running Firmware Telemetry:** Live display of router model, hardware version (`V2.0.2`), firmware version (`V2.0.1EG1T14_TE`), Linux kernel version, SoC architecture, and flash partition offsets.
  - **Cryptographic Firmware Inspector:** Automated file parser verifying ZTE Tag signature (`999999994444444455555555aaaaaaaa`), hardware target model string (`THIS IS H188A VERSION`), LZMA-compressed MIPS32 kernel integrity, and SquashFS 4.0 root filesystem validity.
  - **New Firmware Uploading & Staging:** Safe multipart upload endpoint (`/api/firmware/upload`) with pre-flash integrity verification and critical power-cut safety warnings.
- **Deep Firmware Reverse Engineering:**
  - Successfully carved and analyzed the `H188a.bin` stock binary (11.38 MB).
  - Unpacked the MIPS32 Big-Endian Linux 3.18.21 SMP kernel (uncompressed size: 7.87 MB).
  - Extracted the complete SquashFS 4.0 root filesystem (1,593 files across 54 directories).
  - Documented core daemons: `bin/cspd` (2.59 MB ZTE Central Service Provider Daemon), `bin/httpd` (1.32 MB), and `tc3162_dmt_en7516.ko` (3.3 MB EcoNet VDSL2 driver).
  - Integrated complete reverse engineering findings directly into `README.md`.

### Changed
- Refactored `c:\Users\ahmed\Desktop\ZTE\Run.bat` to detect both `app\` and root workspace directories dynamically.
- Upgraded HTTP server to natively support `HTTP/1.1` persistent connections with explicit connection cleanup.

---

## [2.1.0] - 2026-11-12

### Fixed
- **JavaScript Parsing Crash:** Resolved `SyntaxError: Invalid or unexpected token` caused by unescaped newlines in multiline template literals within the syslog copy routine.
- **Batch Script Instant-Exit:** Resolved Windows CMD OEM Arabic codepage incompatibility by replacing internal Arabic script invocations with a unified, English-encoded runner (`Run.bat`).
- **Port Conflict & `ERR_EMPTY_RESPONSE`:** Added automatic detection and termination of stale or orphaned background processes holding TCP port `8080` upon launcher start.
- **Thread Reentrancy Deadlock:** Switched server locking primitives from `threading.Lock()` to `threading.RLock()` to prevent deadlocks when refreshing router session status.

---

## [2.0.0] - 2026-11-12

### Added
- **Authentic Carrier UI Overhaul:**
  - Completely restyled the web interface to match the official Telecom Egypt (WE) ZTE ZXHN H188A firmware design.
  - Implemented official ZTE CSS layout (`#6F2C91` corporate purple, `#F2F2F2` background, 980px structured container, classic collapsible bars, and zebra-striped form tables).
  - Completely purged all artificial emojis, gamer gradients, and neon badges.
- **Hardware Reboot Controller:**
  - Added official reboot command execution via `deviceManag_lua.lua`.
  - Added modal confirmation dialog with automated 120-second recovery progress bar and reactive polling until the router comes back online.
- **Categorized Syslog Viewer:**
  - Added dedicated System Log tab with real-time text search and filter chips: All, Warnings & Errors, PPPoE & DSL, Wi-Fi & DHCP, Reboots.
  - Added one-click copy to clipboard.

---

## [1.0.0] - 2026-11-11

### Added
- Initial project release for ZTE ZXHN H188A (`V2.0.1EG1T14_TE`).
- Modular Python toolkit (`zte_toolkit`):
  - `client.py`: Session management and hashed token authentication for ZTE web interface.
  - `connection.py`: Automated PPPoE WAN session disconnection and reconnection with cooldown timers.
  - `diagnostics.py`: VDSL physical line telemetry parser (SNR, attenuation, sync rates, CRC/FEC).
  - `logger.py`: Sensitive data redacting log formatter.
- Local HTTP server (`web_app.py`) listening on `127.0.0.1:8080`.

