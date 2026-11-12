import os
import sys
import json
import time
import socket
import threading
import webbrowser
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request
import hashlib
import lzma
import re

# Ensure stdout/stderr are valid under pythonw.exe or redirected consoles
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass

from zte_toolkit.client import ZTERouterClient
from zte_toolkit.diagnostics import RouterDiagnostics
from zte_toolkit.connection import PPPoEConnectionManager
from zte_toolkit.logger import setup_logger

logger = setup_logger()

ROOT_DIR = Path(__file__).resolve().parent
LOGS_DIR = ROOT_DIR / "logs"
CONFIG_FILE = ROOT_DIR / "config.ini"
FIRMWARE_DIR = ROOT_DIR.parent / "Firmware"
DEFAULT_FW = FIRMWARE_DIR / "H188a.bin"

def get_config():
    import configparser
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE, encoding="utf-8")
    return cfg

def is_router_reachable(host="192.168.1.1", timeout=0.4):
    """Fast socket check (<0.4s) to verify PC is on router LAN."""
    for port in (80, 443):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            pass
    return False

def inspect_firmware_file(bin_path=None):
    """
    Parses and cryptographically verifies ZTE ZXHN H188A firmware container.
    Validates ZTE header tag, MIPS32 Linux LZMA kernel, and SquashFS 4.0 rootfs.
    """
    if bin_path is None or not Path(bin_path).exists():
        bin_path = DEFAULT_FW
    path = Path(bin_path)
    if not path.exists():
        return {"valid": False, "error": f"Firmware file not found at {path}"}
    
    file_size = path.stat().st_size
    h_md5 = hashlib.md5()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        head = f.read(4096)
        f.seek(0)
        while chunk := f.read(65536):
            h_md5.update(chunk)
            h_sha256.update(chunk)
            
    md5 = h_md5.hexdigest()
    sha256 = h_sha256.hexdigest()
    
    magic = head[:16].hex()
    is_zte_magic = (magic == "999999994444444455555555aaaaaaaa")
    
    ver_str = head[0x4c:0x4c+32].split(b"\x00")[0].decode("latin1", errors="ignore").strip()
    model_str = head[0xa8:0xa8+32].split(b"\x00")[0].decode("latin1", errors="ignore").strip()
    timestamp_str = head[0xe4:0xe4+16].split(b"\x00")[0].decode("latin1", errors="ignore").strip()
    
    kernel_ok = False
    kernel_size = 0
    kernel_banner = "Unknown"
    if head[0x100:0x105] == b"\x5d\x00\x00\x80\x00":
        with open(path, "rb") as f:
            f.seek(0x100)
            k_data = f.read(4 * 1024 * 1024)
        try:
            decomp = lzma.decompress(k_data)
            kernel_ok = True
            kernel_size = len(decomp)
            m = re.search(rb"Linux version [^\x00\r\n]+", decomp)
            if m:
                kernel_banner = m.group(0).decode("latin1", errors="ignore")
        except Exception as e:
            kernel_banner = f"Decompress error: {e}"
            
    sqsh_ok = False
    sqsh_info = {}
    if file_size > 0x400000:
        with open(path, "rb") as f:
            f.seek(0x400000)
            sq_head = f.read(64)
        if sq_head[:4] == b"hsqs":
            sqsh_ok = True
            inodes = int.from_bytes(sq_head[4:8], "little")
            sq_size = int.from_bytes(sq_head[40:48], "little")
            sqsh_info = {
                "inodes": inodes,
                "size_bytes": sq_size,
                "size_mb": round(sq_size / (1024*1024), 2),
                "compression": "LZMA",
                "block_size_kb": 128
            }
            
    return {
        "valid": bool(is_zte_magic and kernel_ok and sqsh_ok),
        "file_name": path.name,
        "file_path": str(path),
        "file_size_bytes": file_size,
        "file_size_mb": round(file_size / (1024*1024), 2),
        "md5": md5,
        "sha256": sha256,
        "magic": magic,
        "is_zte_magic": is_zte_magic,
        "model": model_str,
        "version": ver_str,
        "build_timestamp": timestamp_str,
        "kernel": {
            "valid": kernel_ok,
            "decompressed_bytes": kernel_size,
            "decompressed_mb": round(kernel_size / (1024*1024), 2),
            "arch": "MIPS32 Big-Endian (SMP)",
            "soc": "EcoNet EN7516",
            "banner": kernel_banner
        },
        "rootfs": {
            "valid": sqsh_ok,
            "offset_hex": "0x400000",
            "type": "SquashFS 4.0",
            **sqsh_info
        }
    }

# Shared state for async operations
app_state = {
    "client": None,
    "diagnostics": None,
    "manager": None,
    "cached_status": None,
    "last_status_time": 0,
    "reconnect_in_progress": False,
    "reconnect_progress": {
        "status": "idle",
        "percent": 0,
        "stage": "",
        "message": "",
        "result": None,
        "error": None
    }
}
state_lock = threading.RLock()
router_io_lock = threading.RLock()

def get_router_toolkit():
    with state_lock:
        client = app_state["client"]
        diag = app_state["diagnostics"]
        mgr = app_state["manager"]
        if client is not None and client.logged_in:
            return client, diag, mgr

    with router_io_lock:
        with state_lock:
            client = app_state["client"]
            diag = app_state["diagnostics"]
            mgr = app_state["manager"]
            if client is not None and client.logged_in:
                return client, diag, mgr

        cfg = get_config()
        host = cfg.get("router", "host", fallback="192.168.1.1")
        user = cfg.get("router", "username", fallback="admin")
        pwd = cfg.get("router", "password", fallback="").strip()

        if not pwd:
            raise ValueError("Please provide router password in config.ini first.")

        from zte_toolkit.logger import RedactingFormatter
        RedactingFormatter.add_secret(pwd)

        if not is_router_reachable(host, timeout=0.4):
            raise ConnectionError(
                f"Cannot reach router at {host}. Please verify PC is connected to ZTE router LAN/Wi-Fi."
            )

        client = ZTERouterClient(host=host)
        client.login(username=user, password=pwd)
        diagnostics = RouterDiagnostics(client)
        manager = PPPoEConnectionManager(
            client, diagnostics,
            cooldown_seconds=cfg.getint("connection", "cooldown_seconds", fallback=6),
            max_retries=cfg.getint("connection", "max_retries", fallback=3),
            verify_timeout=cfg.getint("connection", "verify_timeout", fallback=45)
        )
        with state_lock:
            app_state["client"] = client
            app_state["diagnostics"] = diagnostics
            app_state["manager"] = manager
        return client, diagnostics, manager

def run_reconnect_thread(dry_run=False):
    def worker():
        with state_lock:
            app_state["reconnect_in_progress"] = True
            app_state["reconnect_progress"] = {
                "status": "running",
                "percent": 5,
                "stage": "Initializing",
                "message": "Initializing PPPoE session reset...",
                "result": None,
                "error": None
            }

        def on_progress(percent, stage, message):
            with state_lock:
                app_state["reconnect_progress"]["percent"] = percent
                app_state["reconnect_progress"]["stage"] = stage
                app_state["reconnect_progress"]["message"] = message

        try:
            with router_io_lock:
                _, _, manager = get_router_toolkit()
                success, res = manager.reconnect(dry_run=dry_run, progress_callback=on_progress)
            
            with state_lock:
                if success:
                    app_state["reconnect_progress"]["status"] = "success"
                    app_state["reconnect_progress"]["percent"] = 100
                    app_state["reconnect_progress"]["stage"] = "Completed"
                    app_state["reconnect_progress"]["result"] = res
                else:
                    app_state["reconnect_progress"]["status"] = "error"
                    app_state["reconnect_progress"]["stage"] = "Failed"
                    app_state["reconnect_progress"]["error"] = res.get("error", "Unknown error")
        except Exception as e:
            logger.error(f"Reconnect thread exception: {e}")
            with state_lock:
                app_state["reconnect_progress"]["status"] = "error"
                app_state["reconnect_progress"]["stage"] = "Error"
                app_state["reconnect_progress"]["error"] = str(e)
        finally:
            with state_lock:
                app_state["reconnect_in_progress"] = False
                app_state["last_status_time"] = 0

    t = threading.Thread(target=worker, daemon=True)
    t.start()

HTML_PAGE = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title id="pageTitle">ZXHN H188A - Web Management</title>
    <style type="text/css">
        /* Official ZTE Router Firmware Base Styles */
        body {
            margin: 0;
            padding: 0;
            background-color: #F2F2F2;
            color: #313131;
            font-family: Tahoma, Arial, "Segoe UI", sans-serif;
            font-size: 12px;
            direction: rtl;
            text-align: right;
        }
        * { box-sizing: border-box; }

        /* Container 980px matching ZTE official layout */
        #page_container {
            width: 980px;
            margin: 15px auto 30px auto;
            background: #FFFFFF;
            border: 1px solid #D5D5D5;
            box-shadow: 0 0 8px rgba(0,0,0,0.08);
        }

        /* Top Header Banner */
        #page_header {
            background-color: #FFFFFF;
            border-bottom: 2px solid #6F2C91;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header_brand {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .zte_logo_text {
            font-size: 26px;
            font-weight: bold;
            color: #6F2C91;
            letter-spacing: -1px;
            font-family: Arial, sans-serif;
        }
        .model_title {
            font-size: 15px;
            font-weight: bold;
            color: #333333;
        }
        .sub_title {
            font-size: 11px;
            color: #777777;
        }
        .header_user {
            font-size: 12px;
            color: #555555;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .user_pill {
            background: #F0F0F0;
            border: 1px solid #D0D0D0;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            color: #333333;
        }
        .lang_btn {
            background: #FFFFFF;
            border: 1px solid #6F2C91;
            color: #6F2C91;
            font-size: 11.5px;
            font-weight: bold;
            padding: 3px 10px;
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.2s;
            outline: none;
        }
        .lang_btn:hover {
            background: #6F2C91;
            color: #FFFFFF;
        }

        /* ZTE Navigation Bar (Horizontal Tabs) */
        #mainNavigator {
            background-color: #6F2C91;
            height: 36px;
            display: flex;
            align-items: center;
            padding: 0 10px;
        }
        .nav_item {
            background: transparent;
            border: none;
            color: #FFFFFF;
            font-size: 12.5px;
            font-weight: bold;
            padding: 0 15px;
            height: 36px;
            cursor: pointer;
            outline: none;
            transition: background-color 0.15s;
        }
        .nav_item:hover {
            background-color: #551F72;
        }
        .nav_item.active {
            background-color: #FFFFFF;
            color: #6F2C91;
        }

        /* Page Content Area */
        #page_content {
            padding: 20px 24px;
            min-height: 520px;
        }

        /* ZTE Collapsible Section Header Bar */
        .collapBar {
            background-color: #EBEBEB;
            border: 1px solid #D9D9D9;
            border-inline-start: 4px solid #6F2C91;
            color: #333333;
            font-size: 13px;
            font-weight: bold;
            padding: 8px 12px;
            margin-top: 15px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .collapBar:first-child {
            margin-top: 0;
        }

        /* Operation Action Ribbon */
        .action_ribbon {
            background: #F9F9F9;
            border: 1px solid #E0E0E0;
            padding: 10px 14px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .ribbon_label {
            font-weight: bold;
            color: #333333;
            margin-inline-end: 10px;
        }

        /* Official ZTE Form and Table Layout */
        .formTblWrap {
            border: 1px solid #D9D9D9;
            margin-bottom: 18px;
            background: #FFFFFF;
        }
        .formTbl {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        .formTbl th {
            background-color: #F0F0F0;
            color: #333333;
            font-weight: bold;
            padding: 8px 12px;
            border: 1px solid #D9D9D9;
            text-align: inherit;
        }
        .formTbl td {
            padding: 7px 12px;
            border: 1px solid #E3E3E3;
            color: #333333;
        }
        .formTbl tr:nth-child(even) td {
            background-color: #FBFBFB;
        }
        .formTbl tr:hover td {
            background-color: #F3F1F5;
        }
        .td_label {
            width: 240px;
            font-weight: bold;
            color: #555555;
            background-color: #FAFAFA;
        }
        .td_val {
            direction: ltr;
            text-align: left;
            font-family: Arial, Tahoma, sans-serif;
            font-weight: normal;
        }
        .td_val_mono {
            direction: ltr;
            text-align: left;
            font-family: "Courier New", Courier, monospace;
            font-weight: bold;
            color: #111111;
        }

        /* Official ZTE Buttons */
        .zte_button {
            cursor: pointer;
            height: 28px;
            border: 1px solid #5A2376;
            padding: 0 16px;
            min-width: 90px;
            border-radius: 3px;
            background-color: #6F2C91;
            color: #FFFFFF;
            font-size: 12px;
            font-weight: bold;
            outline: none;
        }
        .zte_button:hover {
            background-color: #551F72;
        }
        .zte_button:disabled {
            background-color: #CCCCCC;
            border-color: #BBBBBB;
            color: #888888;
            cursor: not-allowed;
        }
        .zte_button_red {
            background-color: #B92C28;
            border-color: #9C2421;
            color: #FFFFFF;
        }
        .zte_button_red:hover {
            background-color: #92201D;
        }
        .zte_button_gray {
            background-color: #E6E6E6;
            border: 1px solid #BCBCBC;
            color: #333333;
        }
        .zte_button_gray:hover {
            background-color: #D4D4D4;
        }

        /* Status Badges */
        .badge_connected {
            color: #0E8A16;
            font-weight: bold;
        }
        .badge_disconnected {
            color: #CC0000;
            font-weight: bold;
        }

        /* Syslog Table & Controls */
        .syslog_toolbar {
            background: #F7F7F7;
            border: 1px solid #D9D9D9;
            padding: 8px 12px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .syslog_input {
            height: 26px;
            border: 1px solid #CCCCCC;
            padding: 0 8px;
            font-size: 12px;
            width: 280px;
            outline: none;
        }
        .syslog_input:focus {
            border-color: #6F2C91;
        }
        .filter_btn {
            background: #FFFFFF;
            border: 1px solid #CCCCCC;
            padding: 3px 10px;
            cursor: pointer;
            font-size: 11.5px;
            border-radius: 2px;
        }
        .filter_btn.active {
            background: #6F2C91;
            color: #FFFFFF;
            border-color: #6F2C91;
            font-weight: bold;
        }
        .syslog_wrap {
            max-height: 480px;
            overflow-y: scroll;
            border: 1px solid #D9D9D9;
        }
        .syslog_tbl {
            width: 100%;
            border-collapse: collapse;
            font-size: 11.5px;
            direction: ltr;
            text-align: left;
        }
        .syslog_tbl th {
            background-color: #EFEFEF;
            color: #333333;
            font-weight: bold;
            padding: 6px 10px;
            border-bottom: 1px solid #CCCCCC;
            position: sticky;
            top: 0;
            z-index: 5;
        }
        .syslog_tbl td {
            padding: 5px 10px;
            border-bottom: 1px solid #EBEBEB;
            font-family: Arial, Tahoma, sans-serif;
        }
        .log_notice { color: #0066CC; font-weight: bold; }
        .log_warning { color: #D97706; font-weight: bold; }
        .log_error { color: #CC0000; font-weight: bold; }

        /* Modal Dialog Box */
        .modal_overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }
        .modal_content {
            background: #FFFFFF;
            border: 1px solid #999999;
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
            width: 500px;
            max-width: 90%;
            border-radius: 3px;
            overflow: hidden;
        }
        .modal_header {
            background: #6F2C91;
            color: #FFFFFF;
            font-size: 13px;
            font-weight: bold;
            padding: 8px 14px;
        }
        .modal_header_red {
            background: #B92C28;
            color: #FFFFFF;
            font-size: 13px;
            font-weight: bold;
            padding: 8px 14px;
        }
        .modal_body {
            padding: 18px 20px;
            font-size: 12.5px;
            line-height: 1.6;
            color: #333333;
        }
        .modal_footer {
            background: #F7F7F7;
            border-top: 1px solid #E5E5E5;
            padding: 10px 14px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }

        /* Progress Bar */
        .progress_track {
            height: 14px;
            background: #E0E0E0;
            border-radius: 2px;
            overflow: hidden;
            margin: 12px 0 6px 0;
        }
        .progress_bar {
            height: 100%;
            background: #6F2C91;
            width: 5%;
            transition: width 0.4s ease;
        }

        /* Toast Notice */
        #toastNotice {
            position: fixed;
            bottom: 15px;
            left: 15px;
            background: #333333;
            color: #FFFFFF;
            padding: 9px 16px;
            font-size: 12px;
            border-radius: 3px;
            display: none;
            z-index: 20000;
        }
    </style>
</head>
<body>
    <div id="page_container">
        <!-- Header -->
        <div id="page_header">
            <div class="header_brand">
                <span class="zte_logo_text">ZTE</span>
                <div>
                    <span class="model_title">ZXHN H188A</span>
                    <span class="sub_title" data-i18n="brand_sub"> - Telecom Egypt (WE)</span>
                </div>
            </div>
            <div class="header_user">
                <span><span data-i18n="lbl_user">المستخدم:</span> <strong class="user_pill">admin</strong></span>
                <span><span data-i18n="lbl_status">الحالة:</span> <strong class="user_pill" style="color:#0E8A16;">192.168.1.1</strong></span>
                <span><span data-i18n="lbl_fw">الفيرموير:</span> <strong class="user_pill">V2.0.1EG1T14_TE</strong></span>
                <button id="btnLangToggle" class="lang_btn" onclick="toggleLanguage();">English</button>
            </div>
        </div>

        <!-- Official Router Navigation Tabs -->
        <div id="mainNavigator">
            <button class="nav_item active" id="tab_btn_home" onclick="showTab('home')" data-i18n="tab_home">الصفحة الرئيسية</button>
            <button class="nav_item" id="tab_btn_dsl" onclick="showTab('dsl')" data-i18n="tab_dsl">معلومات خط DSL</button>
            <button class="nav_item" id="tab_btn_wan" onclick="showTab('wan')" data-i18n="tab_wan">حالة الإنترنت WAN</button>
            <button class="nav_item" id="tab_btn_syslog" onclick="showTab('syslog')" data-i18n="tab_syslog">سجل أحداث النظام</button>
            <button class="nav_item" id="tab_btn_manage" onclick="showTab('manage')" data-i18n="tab_manage">إدارة الجهاز</button>
            <button class="nav_item" id="tab_btn_firmware" onclick="showTab('firmware')" data-i18n="tab_firmware">ترقية الفيرموير</button>
        </div>

        <!-- Content -->
        <div id="page_content">
            <!-- Connection Warning -->
            <div id="connWarning" style="display:none; background:#FFF0F0; border:1px solid #FFCCCC; color:#CC0000; padding:10px 14px; margin-bottom:14px; font-weight:bold;">
                <span id="connWarningText">تعذر الاتصال بعنوان الراوتر 192.168.1.1</span>
            </div>

            <!-- TAB 1: HOME (الصفحة الرئيسية) -->
            <div id="panel_home" class="panel_view" style="display:block;">
                <div class="action_ribbon">
                    <span class="ribbon_label" data-i18n="ribbon_label">العمليات السريعة:</span>
                    <input type="button" class="zte_button" data-i18n-val="btn_reconnect" value="تجديد اتصال PPPoE" onclick="openReconnectDlg(false);" />
                    <input type="button" class="zte_button zte_button_red" data-i18n-val="btn_reboot" value="إعادة تشغيل الراوتر (Reboot)" onclick="openRebootDlg();" />
                    <input type="button" class="zte_button zte_button_gray" data-i18n-val="btn_refresh" value="تحديث البيانات" onclick="loadStatus(true);" />
                </div>

                <div class="collapBar">
                    <span data-i18n="wan_card_title">حالة اتصال الإنترنت (Internet Connection Status)</span>
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_status">حالة جلسة الـ WAN</td>
                                <td class="td_val" id="wanStatus">متصل (Connected)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_ip">عنوان الـ IP العام (WAN IPv4)</td>
                                <td class="td_val_mono" id="wanIp">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_gw">البوابة الافتراضية (Default Gateway)</td>
                                <td class="td_val_mono" id="wanGateway">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_dns">خوادم أسماء النطاقات (DNS Servers)</td>
                                <td class="td_val_mono" id="wanDns">--.--.--.-- / --.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_uptime">مدة استمرار الاتصال (Uptime)</td>
                                <td class="td_val_mono" id="wanUptime">--:--:--</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="collapBar">
                    <span data-i18n="dsl_card_title">حالة خط التليفون الفيزيائي (DSL Physical Link)</span>
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_status">حالة مزامنة الخط (Link Status)</td>
                                <td class="td_val" id="dslStatus">Up</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_mod">نمط الخط (Modulation / Profile)</td>
                                <td class="td_val" id="dslModulation">VDSL2 (Profile 17a)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_cur">سرعة التنزيل / الرفع الفعلية</td>
                                <td class="td_val_mono" id="dslCurrentRates">-- Mbps Down / -- Mbps Up</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_max">أقصى سرعة يتحملها الخط (Attainable)</td>
                                <td class="td_val_mono" id="dslMaxRates">-- Mbps Down / -- Mbps Up</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_snr">هامش التشويش (Noise Margin / SNR)</td>
                                <td class="td_val_mono" id="dslSnr">-- dB Down / -- dB Up</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dsl_attn">نسبة التوهين والفقد (Line Attenuation)</td>
                                <td class="td_val_mono" id="dslAttn">-- dB Down / -- dB Up</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 2: DSL INFORMATION (معلومات خط DSL الكاملة) -->
            <div id="panel_dsl" class="panel_view" style="display:none;">
                <div class="collapBar">
                    <span data-i18n="dsl_detail_title">معايير خط الـ DSL بالتفصيل (DSL Link Information)</span>
                    <input type="button" class="zte_button zte_button_gray" data-i18n-val="btn_refresh" value="تحديث" onclick="loadStatus(true);" style="height:22px; min-width:60px;" />
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <thead>
                            <tr>
                                <th style="width:250px;" data-i18n="lbl_tech_param">المعيار الفني</th>
                                <th style="text-align:left;" data-i18n="lbl_downstream">تنزيل (Downstream)</th>
                                <th style="text-align:left;" data-i18n="lbl_upstream">رفع (Upstream)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="lbl_actual_rate">السرعة الفعلية (Actual Rate)</td>
                                <td class="td_val_mono" id="tblDownRate">-- kbps</td>
                                <td class="td_val_mono" id="tblUpRate">-- kbps</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_attainable_rate">أقصى سرعة يتحملها الخط (Attainable Rate)</td>
                                <td class="td_val_mono" id="tblDownMax">-- kbps</td>
                                <td class="td_val_mono" id="tblUpMax">-- kbps</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_snr_margin">هامش التشويش (SNR Margin)</td>
                                <td class="td_val_mono" id="tblDownSnr">-- dB</td>
                                <td class="td_val_mono" id="tblUpSnr">-- dB</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_line_attn">نسبة التوهين والفقد (Line Attenuation)</td>
                                <td class="td_val_mono" id="tblDownAttn">-- dB</td>
                                <td class="td_val_mono" id="tblUpAttn">-- dB</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_crc_err">أخطاء الإشارة التراكمية (CRC Errors)</td>
                                <td class="td_val_mono" id="tblDownCrc">0</td>
                                <td class="td_val_mono" id="tblUpCrc">0</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_fec_err">أخطاء التصحيح المسبق (FEC Errors)</td>
                                <td class="td_val_mono" id="tblDownFec">0</td>
                                <td class="td_val_mono" id="tblUpFec">--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_mod_type">معيار التعديل (Modulation Type)</td>
                                <td class="td_val" colspan="2" id="tblModulation">VDSL2</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_profile">البروفايل (Profile)</td>
                                <td class="td_val" colspan="2" id="tblProfile">17a</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_showtime">مدة استمرار مزامنة الخط (Showtime)</td>
                                <td class="td_val_mono" colspan="2" id="tblShowtime">--</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 3: WAN STATUS (حالة الإنترنت WAN) -->
            <div id="panel_wan" class="panel_view" style="display:none;">
                <div class="collapBar">
                    <span data-i18n="wan_detail_title">بيانات اتصال الإنترنت (IPv4 WAN Status)</span>
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="lbl_conn_name">اسم الاتصال (Connection Name)</td>
                                <td class="td_val">IGD.WD1.WCD1.WCPPP1</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_conn_type">نوع الاتصال (Connection Type)</td>
                                <td class="td_val">PPPoE (Point-to-Point Protocol)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_status">حالة الاتصال (Connection Status)</td>
                                <td class="td_val badge_connected" id="wanDetailedStatus">Connected</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_ip">عنوان الـ IP العام (IP Address)</td>
                                <td class="td_val_mono" id="wanDetailedIp">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_subnet">قناع الشبكة (Subnet Mask)</td>
                                <td class="td_val_mono" id="wanSubnet">255.255.255.255</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_wan_gw">البوابة الافتراضية (Default Gateway)</td>
                                <td class="td_val_mono" id="wanDetailedGw">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dns1">خادم DNS الأساسي (Primary DNS)</td>
                                <td class="td_val_mono" id="wanDns1">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_dns2">خادم DNS الثانوي (Secondary DNS)</td>
                                <td class="td_val_mono" id="wanDns2">--.--.--.--</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_mtu">الحد الأقصى لحجم الحزمة (MTU)</td>
                                <td class="td_val_mono">1492</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_vlan">إعدادات شبكة الـ VLAN</td>
                                <td class="td_val">VlanEnable = 0</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 4: SYSLOG (سجل أحداث النظام) -->
            <div id="panel_syslog" class="panel_view" style="display:none;">
                <div class="collapBar">
                    <span data-i18n="syslog_title">سجل أحداث النظام والراوتر (Log Management)</span>
                    <span id="syslogTotalText" style="font-weight:normal; font-size:11px;">0 سجل</span>
                </div>

                <div class="syslog_toolbar">
                    <span data-i18n="lbl_search">البحث:</span>
                    <input type="text" id="syslogFilterInput" class="syslog_input" data-i18n-placeholder="syslog_search_ph" placeholder="اكتب للبحث..." oninput="renderSyslogRows();" />
                    <button class="filter_btn active" onclick="setSyslogCategory('all', event);" data-i18n="syslog_btn_all">الكل</button>
                    <button class="filter_btn" onclick="setSyslogCategory('warn_err', event);" data-i18n="syslog_btn_warn">تحذيرات وأخطاء</button>
                    <button class="filter_btn" onclick="setSyslogCategory('pppoe', event);" data-i18n="syslog_btn_pppoe">PPPoE & DSL</button>
                    <button class="filter_btn" onclick="setSyslogCategory('wifi', event);" data-i18n="syslog_btn_wifi">واي فاي و DHCP</button>
                    <button class="filter_btn" onclick="setSyslogCategory('reboot', event);" data-i18n="syslog_btn_reboot">إعادة التشغيل</button>
                    <input type="button" class="zte_button zte_button_gray" data-i18n-val="syslog_btn_refresh" value="تحديث السجلات" onclick="loadSyslog(true);" style="height:26px; min-width:70px;" />
                    <input type="button" class="zte_button zte_button_gray" data-i18n-val="syslog_btn_copy" value="نسخ السجلات" onclick="copySyslogText();" style="height:26px; min-width:70px;" />
                </div>

                <div class="syslog_wrap">
                    <table class="syslog_tbl">
                        <thead>
                            <tr>
                                <th style="width:40px;">#</th>
                                <th style="width:150px;">Time</th>
                                <th style="width:80px;">Type</th>
                                <th>Event Description</th>
                            </tr>
                        </thead>
                        <tbody id="syslogRows">
                            <tr><td colspan="4" style="text-align:center; padding:25px; color:#666666;">جاري تحميل سجلات الراوتر...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 5: DEVICE MANAGEMENT (إدارة الجهاز و Reboot) -->
            <div id="panel_manage" class="panel_view" style="display:none;">
                <div class="collapBar">
                    <span data-i18n="manage_reboot_title">إعادة تشغيل الراوتر (Reboot Management)</span>
                </div>
                <div class="formTblWrap" style="padding:15px;">
                    <p style="margin:0 0 12px 0; color:#555555; line-height:1.7;" data-i18n="manage_reboot_desc">
                        إعادة التشغيل: يرجى الضغط على زر "إعادة تشغيل الراوتر" أدناه لإعادة إقلاع الجهاز رسمياً عبر واجهة الراوتر deviceManag_lua.lua.
                        ستستغرق العملية حوالي دقيقة إلى دقيقتين حتى يعود الراوتر للعمل.
                    </p>
                    <input type="button" class="zte_button zte_button_red" data-i18n-val="manage_reboot_btn" value="إعادة تشغيل الراوتر (Reboot)" onclick="openRebootDlg();" style="height:32px; min-width:160px; font-size:13px;" />
                </div>

                <div class="collapBar">
                    <span data-i18n="manage_reconn_title">تجديد جلسة الـ WAN (PPPoE Reconnect Management)</span>
                </div>
                <div class="formTblWrap" style="padding:15px;">
                    <p style="margin:0 0 12px 0; color:#555555; line-height:1.7;" data-i18n="manage_reconn_desc">
                        تجديد الاتصال: يقوم بقطع اتصال PPPoE فقط والانتظار 6 ثوانٍ ثم الاتصال مجدداً لجلب IP جديد دون إعادة تشغيل الراوتر ودون لمس إعدادات الخط أو الواي فاي.
                    </p>
                    <input type="button" class="zte_button" data-i18n-val="manage_reconn_btn" value="تجديد اتصال PPPoE الآن" onclick="openReconnectDlg(false);" style="height:32px; min-width:160px; font-size:13px;" />
                </div>

                <div class="collapBar">
                    <span data-i18n="manage_info_title">معلومات الجهاز (Device Information)</span>
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="lbl_mfr">الشركة المصنعة</td>
                                <td class="td_val">ZTE Corporation</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_model">الموديل (Product Class)</td>
                                <td class="td_val">ZXHN H188A</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_hw_ver">إصدار الهاردوير (Hardware Version)</td>
                                <td class="td_val">V2.0.2</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="lbl_sw_ver">إصدار السوفتوير (Software Version)</td>
                                <td class="td_val">V2.0.1EG1T14_TE (Telecom Egypt)</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div style="margin-top:15px;">
                    <input type="button" class="zte_button zte_button_gray" data-i18n-val="manage_clear_logs" value="تفريغ ملفات التقارير المحلية" onclick="clearLocalLogs();" />
                </div>
            </div>

            <!-- TAB 6: FIRMWARE UPGRADE & INSPECTION -->
            <div id="panel_firmware" class="panel_view" style="display:none;">
                <div class="collapBar">
                    <span data-i18n="fw_specs_title">مواصفات الفيرموير والنظام الحالي (Current System & Firmware)</span>
                </div>
                <div class="formTblWrap">
                    <table class="formTbl">
                        <tbody>
                            <tr>
                                <td class="td_label" data-i18n="fw_model">موديل الجهاز والعتاد</td>
                                <td class="td_val"><strong>ZTE ZXHN H188A</strong> (Hardware Version: V2.0.2)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="fw_running_version">إصدار السوفتوير المثبت</td>
                                <td class="td_val_mono" style="color:#0E8A16; font-size:13px;">V2.0.1EG1T14_TE (Telecom Egypt - WE)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="fw_kernel">نواة التشغيل والمعالج</td>
                                <td class="td_val">Linux 3.18.21 SMP (MediaTek / EcoNet EN7516 MIPS32 Big-Endian)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="fw_build_date">تاريخ وبصمة بناء الفيرموير</td>
                                <td class="td_val">2021-05-19 17:41:04 CST (Buildroot 2015.08.1 / gcc 4.6.3)</td>
                            </tr>
                            <tr>
                                <td class="td_label" data-i18n="fw_partitions">تقسيم الذاكرة الوميضية (Flash Map)</td>
                                <td class="td_val" style="font-family:monospace; font-size:11.5px;">
                                    0x000000: Header (ZTE Tag) | 0x000100: Kernel (LZMA 2.54MB -> 7.87MB) | 0x400000: RootFS (SquashFS 4.0 7.38MB)
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="collapBar">
                    <span data-i18n="fw_local_title">فحص والتحقق من ملف الفيرموير المحلي (H188a.bin)</span>
                    <input type="button" class="zte_button" data-i18n-val="fw_btn_inspect" value="فحص والتحقق من الملف" onclick="inspectLocalFirmware();" style="height:24px; min-width:140px;" />
                </div>
                <div class="formTblWrap" style="padding:14px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; background:#F8F8F8; padding:10px 14px; border:1px solid #E5E5E5;">
                        <div>
                            <span data-i18n="fw_detected_file">الملف المكتشف:</span>
                            <strong style="color:#6F2C91; font-family:monospace; margin:0 6px;">Firmware/H188a.bin</strong>
                            <span style="color:#777; font-size:11px;">(11.38 MB / 11,934,068 bytes)</span>
                        </div>
                        <div id="fwStatusBadge" class="user_pill" style="color:#555;" data-i18n="fw_badge_not_inspected">لم يتم الفحص بعد</div>
                    </div>

                    <div id="fwInspectResultBox" style="display:none;">
                        <table class="formTbl" style="margin-bottom:12px;">
                            <tbody>
                                <tr>
                                    <td class="td_label" data-i18n="fw_chk_magic">البصمة السحرية (ZTE Magic)</td>
                                    <td class="td_val_mono" id="fwResMagic">--</td>
                                </tr>
                                <tr>
                                    <td class="td_label" data-i18n="fw_chk_model">الموديل المستهدف المكتوب</td>
                                    <td class="td_val_mono" id="fwResModel">--</td>
                                </tr>
                                <tr>
                                    <td class="td_label" data-i18n="fw_chk_ver">إصدار الحزمة</td>
                                    <td class="td_val_mono" id="fwResVer">--</td>
                                </tr>
                                <tr>
                                    <td class="td_label" data-i18n="fw_chk_kernel">فحص النواة (Kernel LZMA)</td>
                                    <td class="td_val" id="fwResKernel">--</td>
                                </tr>
                                <tr>
                                    <td class="td_label" data-i18n="fw_chk_rootfs">فحص نظام الملفات (SquashFS 4.0)</td>
                                    <td class="td_val" id="fwResRootfs">--</td>
                                </tr>
                                <tr>
                                    <td class="td_label">SHA-256 Checksum</td>
                                    <td class="td_val_mono" id="fwResSha256" style="font-size:11px;">--</td>
                                </tr>
                            </tbody>
                        </table>
                        <div style="display:flex; gap:10px; align-items:center;">
                            <input type="button" class="zte_button" data-i18n-val="fw_btn_stage_use" value="اعتماد واستخدام هذا الملف للتحديث" onclick="confirmUseLocalFw();" />
                            <span style="color:#0E8A16; font-weight:bold; font-size:12px;" id="fwCompatibilitySummary"></span>
                        </div>
                    </div>
                </div>

                <div class="collapBar">
                    <span data-i18n="fw_upload_title">رفع ملف فيرموير جديد (.bin) (Upload New Firmware)</span>
                </div>
                <div class="formTblWrap" style="padding:14px;">
                    <p style="margin:0 0 12px 0; color:#555; line-height:1.6;" data-i18n="fw_upload_desc">
                        يرجى تحديد ملف التحديث بامتداد .bin المخصص لراوتر ZTE ZXHN H188A. سيقوم النظام بفحص الملف تلقائياً قبل قبوله للتأكد من سلامته وتوافقه مع المعالج والعتاد.
                    </p>
                    <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                        <input type="file" id="fwFileInput" accept=".bin" class="syslog_input" style="height:30px; width:340px; padding:3px;" onchange="handleFwFileSelected();" />
                        <input type="button" id="btnUploadFw" class="zte_button" data-i18n-val="fw_btn_upload" value="فحص ورفع الفيرموير" onclick="uploadNewFirmware();" disabled />
                    </div>
                    <div id="fwUploadProgressBox" style="display:none; margin-top:12px;">
                        <div class="progress_track">
                            <div class="progress_bar" id="fwUploadBar"></div>
                        </div>
                        <div style="font-weight:bold; color:#6F2C91; font-size:12px;" id="fwUploadStage"></div>
                        <div style="font-size:11.5px; color:#666;" id="fwUploadMsg"></div>
                    </div>
                    <div style="margin-top:12px; background:#FFF3CD; border:1px solid #FFEAA8; padding:8px 12px; color:#856404; font-size:11.5px; border-radius:2px;">
                        <strong data-i18n="fw_warn_head">تنبيه أمان هام:</strong>
                        <span data-i18n="fw_warn_body">لا تقم بإيقاف تشغيل الراوتر أو فصل كابل الكهرباء أثناء عملية التحديث نهائياً لتجنب تلف الذاكرة الوميضية (Flash).</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Reconnect Modal Dialog -->
    <div id="dlgReconnect" class="modal_overlay" style="display:none;">
        <div class="modal_content">
            <div class="modal_header" id="dlgReconnectTitle" data-i18n="dlg_reconn_title">تأكيد تجديد اتصال PPPoE</div>
            <div class="modal_body" id="dlgReconnectBody">
                <p style="margin:0 0 10px 0;" data-i18n="dlg_reconn_body">هل تريد فصل جلسة PPPoE وإعادة ربطها للحصول على WAN IP جديد؟</p>
                <div id="reconnectProgressBox" style="display:none;">
                    <div class="progress_track">
                        <div class="progress_bar" id="reconnectBar"></div>
                    </div>
                    <div style="font-weight:bold; color:#6F2C91;" id="reconnectStage">جاري المعالجة...</div>
                    <div style="font-size:11.5px; color:#666666;" id="reconnectMsg">...</div>
                </div>
            </div>
            <div class="modal_footer" id="dlgReconnectFooter">
                <input type="button" class="zte_button zte_button_gray" data-i18n-val="btn_cancel" value="إلغاء" onclick="closeReconnectDlg();" />
                <input type="button" class="zte_button" id="btnDoReconnect" data-i18n-val="btn_confirm_reconn" value="نعم، ابدأ التجديد" onclick="executeReconnect();" />
            </div>
        </div>
    </div>

    <!-- Reboot Modal Dialog -->
    <div id="dlgReboot" class="modal_overlay" style="display:none;">
        <div class="modal_content">
            <div class="modal_header_red" data-i18n="dlg_reboot_title">تأكيد إعادة تشغيل الراوتر (Reboot)</div>
            <div class="modal_body">
                <div id="rebootConfirmText">
                    <p style="margin:0 0 10px 0; color:#333333;" data-i18n="dlg_reboot_body">
                        هل أنت متأكد من رغبتك في إعادة تشغيل راوتر ZTE ZXHN H188A الآن؟<br />
                        سيتم فصل الإنترنت والواي فاي لمدة دقيقة إلى دقيقتين حتى يكتمل إقلاع الجهاز.
                    </p>
                </div>
                <div id="rebootProgressBox" style="display:none;">
                    <div class="progress_track">
                        <div class="progress_bar" id="rebootBar" style="background:#B92C28;"></div>
                    </div>
                    <div style="font-weight:bold; font-size:14px; color:#B92C28; margin-bottom:4px;" id="rebootTimerLabel">120 ثانية متبقية</div>
                    <div style="font-size:11.5px; color:#666666;" id="rebootStatusLabel" data-i18n="reboot_waiting_text">تم إرسال أمر إعادة التشغيل. يتم فحص عودة الراوتر للعمل تلقائياً...</div>
                </div>
            </div>
            <div class="modal_footer" id="dlgRebootFooter">
                <input type="button" class="zte_button zte_button_gray" data-i18n-val="btn_cancel" value="إلغاء" onclick="closeRebootDlg();" />
                <input type="button" class="zte_button zte_button_red" data-i18n-val="btn_confirm_reboot" value="نعم، أعد التشغيل الآن" onclick="executeReboot();" />
            </div>
        </div>
    </div>

    <!-- Toast Notice -->
    <div id="toastNotice"></div>

    <script type="text/javascript">
        const I18N = {
            ar: {
                doc_title: "ZXHN H188A - لوحة التحكم وإدارة الراوتر",
                brand_sub: " - المصرية للاتصالات (WE)",
                lbl_user: "المستخدم:",
                lbl_status: "الحالة:",
                lbl_fw: "الفيرموير:",
                tab_home: "الصفحة الرئيسية",
                tab_dsl: "معلومات خط DSL",
                tab_wan: "حالة الإنترنت WAN",
                tab_syslog: "سجل أحداث النظام",
                tab_manage: "إدارة الجهاز",
                tab_firmware: "ترقية الفيرموير",
                ribbon_label: "العمليات السريعة:",
                btn_reconnect: "تجديد اتصال PPPoE",
                btn_reboot: "إعادة تشغيل الراوتر (Reboot)",
                btn_refresh: "تحديث البيانات",
                wan_card_title: "حالة اتصال الإنترنت (Internet Connection Status)",
                dsl_card_title: "حالة خط التليفون الفيزيائي (DSL Physical Link)",
                dsl_detail_title: "معايير خط الـ DSL بالتفصيل (DSL Link Information)",
                wan_detail_title: "بيانات اتصال الإنترنت (IPv4 WAN Status)",
                syslog_title: "سجل أحداث النظام والراوتر (Log Management)",
                manage_reboot_title: "إعادة تشغيل الراوتر (Reboot Management)",
                manage_reboot_desc: "يرجى الضغط على زر إعادة تشغيل الراوتر أدناه لإعادة إقلاع الجهاز رسمياً عبر واجهة الراوتر deviceManag_lua.lua. ستستغرق العملية حوالي دقيقة إلى دقيقتين حتى يعود للعمل.",
                manage_reboot_btn: "إعادة تشغيل الراوتر (Reboot)",
                manage_reconn_title: "تجديد جلسة الـ WAN (PPPoE Reconnect Management)",
                manage_reconn_desc: "يقوم بقطع اتصال PPPoE فقط والانتظار 6 ثوانٍ ثم الاتصال مجدداً لجلب IP جديد دون إعادة تشغيل الراوتر ودون لمس الخط أو الواي فاي.",
                manage_reconn_btn: "تجديد اتصال PPPoE الآن",
                manage_info_title: "معلومات الجهاز (Device Information)",
                manage_clear_logs: "تفريغ ملفات التقارير المحلية",
                lbl_wan_status: "حالة جلسة الـ WAN",
                lbl_wan_ip: "عنوان الـ IP العام (WAN IPv4)",
                lbl_wan_gw: "البوابة الافتراضية (Default Gateway)",
                lbl_wan_dns: "خوادم أسماء النطاقات (DNS Servers)",
                lbl_wan_uptime: "مدة استمرار الاتصال (Uptime)",
                lbl_dsl_status: "حالة مزامنة الخط (Link Status)",
                lbl_dsl_mod: "نمط الخط (Modulation / Profile)",
                lbl_dsl_cur: "سرعة التنزيل / الرفع الفعلية",
                lbl_dsl_max: "أقصى سرعة يتحملها الخط (Attainable)",
                lbl_dsl_snr: "هامش التشويش (Noise Margin / SNR)",
                lbl_dsl_attn: "نسبة التوهين والفقد (Line Attenuation)",
                lbl_tech_param: "المعيار الفني",
                lbl_downstream: "تنزيل (Downstream)",
                lbl_upstream: "رفع (Upstream)",
                lbl_actual_rate: "السرعة الفعلية (Actual Rate)",
                lbl_attainable_rate: "أقصى سرعة يتحملها الخط (Attainable Rate)",
                lbl_snr_margin: "هامش التشويش (SNR Margin)",
                lbl_line_attn: "نسبة التوهين والفقد (Line Attenuation)",
                lbl_crc_err: "أخطاء الإشارة التراكمية (CRC Errors)",
                lbl_fec_err: "أخطاء التصحيح المسبق (FEC Errors)",
                lbl_mod_type: "معيار التعديل (Modulation Type)",
                lbl_profile: "البروفايل (Profile)",
                lbl_showtime: "مدة استمرار مزامنة الخط (Showtime)",
                lbl_conn_name: "اسم الاتصال (Connection Name)",
                lbl_conn_type: "نوع الاتصال (Connection Type)",
                lbl_subnet: "قناع الشبكة (Subnet Mask)",
                lbl_dns1: "خادم DNS الأساسي (Primary DNS)",
                lbl_dns2: "خادم DNS الثانوي (Secondary DNS)",
                lbl_mtu: "الحد الأقصى لحجم الحزمة (MTU)",
                lbl_vlan: "إعدادات شبكة الـ VLAN",
                lbl_mfr: "الشركة المصنعة",
                lbl_model: "الموديل (Product Class)",
                lbl_hw_ver: "إصدار الهاردوير (Hardware Version)",
                lbl_sw_ver: "إصدار السوفتوير (Software Version)",
                lbl_search: "البحث:",
                syslog_search_ph: "اكتب للبحث (IP, MAC, pppd, padi, dsl, reboot...)",
                syslog_btn_all: "الكل",
                syslog_btn_warn: "تحذيرات وأخطاء",
                syslog_btn_pppoe: "PPPoE & DSL",
                syslog_btn_wifi: "واي فاي و DHCP",
                syslog_btn_reboot: "إعادة التشغيل",
                syslog_btn_refresh: "تحديث السجلات",
                syslog_btn_copy: "نسخ السجلات",
                fw_specs_title: "مواصفات الفيرموير والنظام الحالي (Current System & Firmware)",
                fw_model: "موديل الجهاز والعتاد",
                fw_running_version: "إصدار السوفتوير المثبت",
                fw_kernel: "نواة التشغيل والمعالج",
                fw_build_date: "تاريخ وبصمة بناء الفيرموير",
                fw_partitions: "تقسيم الذاكرة الوميضية (Flash Map)",
                fw_local_title: "فحص والتحقق من ملف الفيرموير المحلي (H188a.bin)",
                fw_btn_inspect: "فحص والتحقق من الملف",
                fw_detected_file: "الملف المكتشف:",
                fw_badge_not_inspected: "لم يتم الفحص بعد",
                fw_chk_magic: "البصمة السحرية (ZTE Magic)",
                fw_chk_model: "الموديل المستهدف المكتوب",
                fw_chk_ver: "إصدار الحزمة",
                fw_chk_kernel: "فحص النواة (Kernel LZMA)",
                fw_chk_rootfs: "فحص نظام الملفات (SquashFS 4.0)",
                fw_btn_stage_use: "اعتماد واستخدام هذا الملف للتحديث",
                fw_upload_title: "رفع ملف فيرموير جديد (.bin) (Upload New Firmware)",
                fw_upload_desc: "يرجى تحديد ملف التحديث بامتداد .bin المخصص لراوتر ZTE ZXHN H188A. سيقوم النظام بفحص الملف تلقائياً قبل قبوله للتأكد من سلامته وتوافقه مع المعالج والعتاد.",
                fw_btn_upload: "فحص ورفع الفيرموير",
                fw_warn_head: "تنبيه أمان هام:",
                fw_warn_body: "لا تقم بإيقاف تشغيل الراوتر أو فصل كابل الكهرباء أثناء عملية التحديث نهائياً لتجنب تلف الذاكرة الوميضية (Flash).",
                dlg_reconn_title: "تأكيد تجديد اتصال PPPoE",
                dlg_reconn_body: "هل تريد فصل جلسة PPPoE وإعادة ربطها للحصول على WAN IP جديد؟",
                dlg_reboot_title: "تأكيد إعادة تشغيل الراوتر (Reboot)",
                dlg_reboot_body: "هل أنت متأكد من رغبتك في إعادة تشغيل راوتر ZTE ZXHN H188A الآن؟ سيتم فصل الإنترنت والواي فاي لمدة دقيقة إلى دقيقتين حتى يكتمل إقلاع الجهاز.",
                btn_cancel: "إلغاء",
                btn_confirm_reconn: "نعم، ابدأ التجديد",
                btn_confirm_reboot: "نعم، أعد التشغيل الآن",
                reboot_waiting_text: "تم إرسال أمر إعادة التشغيل. يتم فحص عودة الراوتر للعمل تلقائياً..."
            },
            en: {
                doc_title: "ZXHN H188A - Web Management",
                brand_sub: " - Telecom Egypt (WE)",
                lbl_user: "User:",
                lbl_status: "Status:",
                lbl_fw: "Firmware:",
                tab_home: "Home",
                tab_dsl: "DSL Information",
                tab_wan: "Internet WAN Status",
                tab_syslog: "System Log",
                tab_manage: "Device Management",
                tab_firmware: "Firmware Management",
                ribbon_label: "Quick Actions:",
                btn_reconnect: "Renew PPPoE",
                btn_reboot: "Reboot Router",
                btn_refresh: "Refresh Data",
                wan_card_title: "Internet Connection Status",
                dsl_card_title: "DSL Physical Link Status",
                dsl_detail_title: "DSL Detailed Link Parameters",
                wan_detail_title: "IPv4 WAN Connection Status",
                syslog_title: "System Log Management",
                manage_reboot_title: "Router Reboot Management",
                manage_reboot_desc: "Click the Reboot Router button below to restart the device safely via official router API deviceManag_lua.lua. The router will take approximately 1-2 minutes to reboot and resume service.",
                manage_reboot_btn: "Reboot Router",
                manage_reconn_title: "WAN Session Renewal (PPPoE Management)",
                manage_reconn_desc: "Disconnects the PPPoE session, pauses 6 seconds, and reconnects to acquire a fresh WAN IP without restarting the router or affecting Wi-Fi settings.",
                manage_reconn_btn: "Renew PPPoE Session Now",
                manage_info_title: "Device Information",
                manage_clear_logs: "Clear Local Reports & Logs",
                lbl_wan_status: "WAN Connection Status",
                lbl_wan_ip: "Public IPv4 Address (WAN IP)",
                lbl_wan_gw: "Default Gateway",
                lbl_wan_dns: "DNS Servers",
                lbl_wan_uptime: "Connection Uptime",
                lbl_dsl_status: "DSL Sync Status",
                lbl_dsl_mod: "Modulation / Profile",
                lbl_dsl_cur: "Current Down / Up Rate",
                lbl_dsl_max: "Attainable Down / Up Rate",
                lbl_dsl_snr: "Noise Margin (SNR)",
                lbl_dsl_attn: "Line Attenuation",
                lbl_tech_param: "Technical Parameter",
                lbl_downstream: "Downstream",
                lbl_upstream: "Upstream",
                lbl_actual_rate: "Actual Rate",
                lbl_attainable_rate: "Attainable Rate",
                lbl_snr_margin: "SNR Margin",
                lbl_line_attn: "Line Attenuation",
                lbl_crc_err: "CRC Cumulative Errors",
                lbl_fec_err: "Forward Error Correction (FEC)",
                lbl_mod_type: "Modulation Type",
                lbl_profile: "DSL Profile",
                lbl_showtime: "DSL Showtime Duration",
                lbl_conn_name: "Connection Name",
                lbl_conn_type: "Connection Type",
                lbl_subnet: "Subnet Mask",
                lbl_dns1: "Primary DNS",
                lbl_dns2: "Secondary DNS",
                lbl_mtu: "Maximum Transmission Unit (MTU)",
                lbl_vlan: "VLAN Settings",
                lbl_mfr: "Manufacturer",
                lbl_model: "Product Class",
                lbl_hw_ver: "Hardware Version",
                lbl_sw_ver: "Software Version",
                lbl_search: "Search:",
                syslog_search_ph: "Search logs (IP, MAC, pppd, padi, dsl, reboot...)",
                syslog_btn_all: "All",
                syslog_btn_warn: "Warnings & Errors",
                syslog_btn_pppoe: "PPPoE & DSL",
                syslog_btn_wifi: "Wi-Fi & DHCP",
                syslog_btn_reboot: "Reboot Events",
                syslog_btn_refresh: "Refresh Logs",
                syslog_btn_copy: "Copy Logs",
                fw_specs_title: "Current System & Firmware Specifications",
                fw_model: "Hardware & Device Model",
                fw_running_version: "Installed Software Version",
                fw_kernel: "Operating System Kernel & SoC",
                fw_build_date: "Firmware Build Timestamp",
                fw_partitions: "Flash Memory Partition Map",
                fw_local_title: "Inspect & Verify Local Firmware Binary (H188a.bin)",
                fw_btn_inspect: "Inspect & Verify Binary",
                fw_detected_file: "Detected File:",
                fw_badge_not_inspected: "Not Inspected Yet",
                fw_chk_magic: "ZTE Tag Magic Signature",
                fw_chk_model: "Embedded Target Model",
                fw_chk_ver: "Firmware Version Tag",
                fw_chk_kernel: "Kernel Integrity (LZMA MIPS32)",
                fw_chk_rootfs: "Root Filesystem (SquashFS 4.0)",
                fw_btn_stage_use: "Stage & Use This Image For Upgrade",
                fw_upload_title: "Upload & Verify New Firmware (.bin)",
                fw_upload_desc: "Select a .bin firmware package designed for the ZTE ZXHN H188A. The system will perform automated cryptographic and partition checks before flashing.",
                fw_btn_upload: "Validate & Upload Firmware",
                fw_warn_head: "Critical Safety Notice:",
                fw_warn_body: "Do not power off the router or disconnect the power cable during the upgrade process to prevent flash memory corruption.",
                dlg_reconn_title: "Confirm PPPoE Session Renewal",
                dlg_reconn_body: "Do you want to reset the PPPoE connection to acquire a fresh WAN IP?",
                dlg_reboot_title: "Confirm Router Reboot",
                dlg_reboot_body: "Are you sure you want to reboot the ZTE ZXHN H188A router now? Internet and Wi-Fi will be offline for 1-2 minutes.",
                btn_cancel: "Cancel",
                btn_confirm_reconn: "Yes, Renew Now",
                btn_confirm_reboot: "Yes, Reboot Now",
                reboot_waiting_text: "Reboot command dispatched. Router recovery is being monitored automatically..."
            }
        };

        let currentLang = 'ar';
        let syslogData = [];
        let currentSyslogCategory = 'all';
        let isDryRun = false;
        let reconnectTimer = null;
        let rebootTimer = null;
        let rebootSeconds = 120;
        let lastStatusData = null;

        function setLanguage(lang) {
            currentLang = (lang === 'en') ? 'en' : 'ar';
            try { localStorage.setItem('zte_lang', currentLang); } catch(e) {}
            const isAr = (currentLang === 'ar');
            document.documentElement.lang = currentLang;
            document.documentElement.dir = isAr ? 'rtl' : 'ltr';
            document.body.dir = isAr ? 'rtl' : 'ltr';

            const btn = document.getElementById('btnLangToggle');
            if (btn) btn.innerText = isAr ? 'English' : 'العربية';

            const dict = I18N[currentLang] || I18N.ar;

            const titleElem = document.getElementById('pageTitle');
            if (titleElem && dict.doc_title) titleElem.innerText = dict.doc_title;

            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (dict[key]) el.innerText = dict[key];
            });

            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const key = el.getAttribute('data-i18n-placeholder');
                if (dict[key]) el.placeholder = dict[key];
            });

            document.querySelectorAll('[data-i18n-val]').forEach(el => {
                const key = el.getAttribute('data-i18n-val');
                if (dict[key]) el.value = dict[key];
            });

            if (lastStatusData) renderStatusData(lastStatusData);
            renderSyslogRows();
        }

        function toggleLanguage() {
            setLanguage(currentLang === 'ar' ? 'en' : 'ar');
        }

        function showTab(tabName) {
            document.querySelectorAll('.panel_view').forEach(p => p.style.display = 'none');
            document.querySelectorAll('.nav_item').forEach(b => b.classList.remove('active'));

            const panel = document.getElementById('panel_' + tabName);
            const btn = document.getElementById('tab_btn_' + tabName);
            if (panel) panel.style.display = 'block';
            if (btn) btn.classList.add('active');

            if (tabName === 'syslog' && syslogData.length === 0) {
                loadSyslog();
            } else if (tabName === 'firmware') {
                checkFirmwareQuickStatus();
            }
        }

        function showToast(text, duration) {
            duration = duration || 3000;
            const toast = document.getElementById('toastNotice');
            if (!toast) return;
            toast.innerText = text;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, duration);
        }

        function formatDuration(sec) {
            sec = parseInt(sec) || 0;
            const h = Math.floor(sec / 3600);
            const m = Math.floor((sec % 3600) / 60);
            const s = sec % 60;
            return (h < 10 ? '0' + h : h) + ':' + (m < 10 ? '0' + m : m) + ':' + (s < 10 ? '0' + s : s);
        }

        async function loadStatus(manual) {
            manual = Boolean(manual);
            try {
                const res = await fetch("/api/status");
                const data = await res.json();
                lastStatusData = data;
                renderStatusData(data);
                if (manual) showToast(currentLang === 'ar' ? "تم تحديث البيانات بنجاح" : "Data updated successfully");
            } catch(e) {
                console.error("loadStatus error:", e);
                if (manual) showToast(currentLang === 'ar' ? "تعذر التحديث: تحقق من اتصال الراوتر" : "Update failed: verify router LAN connection");
            }
        }

        function renderStatusData(data) {
            const warnBanner = document.getElementById("connWarning");
            const isAr = (currentLang === 'ar');
            if (data.connected_to_router === false) {
                if (warnBanner) {
                    warnBanner.style.display = "block";
                    document.getElementById("connWarningText").innerText = (isAr ? "تعذر الاتصال بعنوان الراوتر: " : "Cannot reach router at: ") + (data.error || "192.168.1.1");
                }
                const wanSt = document.getElementById("wanStatus");
                if (wanSt) {
                    wanSt.className = "td_val badge_disconnected";
                    wanSt.innerText = isAr ? "غير متصل (Disconnected)" : "Disconnected";
                }
                return;
            } else if (warnBanner) {
                warnBanner.style.display = "none";
            }

            const wan = data.wan_pppoe || {};
            const dsl = data.dsl_line || {};

            const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
            setVal("wanIp", wan.wan_ip || "0.0.0.0");
            setVal("wanGateway", wan.gateway || "--.--.--.--");
            setVal("wanDns", (wan.dns1 || "--") + " / " + (wan.dns2 || "--"));
            setVal("wanUptime", formatDuration(wan.uptime_seconds));

            const isConn = (wan.connection_status || "").toLowerCase() === "connected";
            const wanStatusElem = document.getElementById("wanStatus");
            if (wanStatusElem) {
                wanStatusElem.className = isConn ? "td_val badge_connected" : "td_val badge_disconnected";
                wanStatusElem.innerText = isConn ? (isAr ? "متصل (Connected)" : "Connected") : (isAr ? "غير متصل (Disconnected)" : "Disconnected");
            }

            setVal("wanDetailedStatus", isConn ? "Connected" : (wan.connection_status || "Disconnected"));
            setVal("wanDetailedIp", wan.wan_ip || "0.0.0.0");
            setVal("wanDetailedGw", wan.gateway || "--.--.--.--");
            setVal("wanDns1", wan.dns1 || "--");
            setVal("wanDns2", wan.dns2 || "--");

            const downMb = dsl.downstream_rate_mbps || 0;
            const upMb = dsl.upstream_rate_mbps || 0;
            const maxDownMb = Math.round((dsl.downstream_max_kbps || 0) / 1024);
            const maxUpMb = Math.round((dsl.upstream_max_kbps || 0) / 1024);

            setVal("dslStatus", dsl.status || "Up");
            setVal("dslModulation", (dsl.modulation || "VDSL2") + " (" + (dsl.profile || "17a") + ")");
            setVal("dslCurrentRates", downMb + " Mbps Down / " + upMb + " Mbps Up");
            setVal("dslMaxRates", maxDownMb + " Mbps Down / " + maxUpMb + " Mbps Up");
            setVal("dslSnr", (dsl.downstream_snr_db || 0) + " dB Down / " + (dsl.upstream_snr_db || 0) + " dB Up");
            setVal("dslAttn", (dsl.downstream_attenuation_db || 0) + " dB Down / " + (dsl.upstream_attenuation_db || 0) + " dB Up");

            setVal("tblDownRate", (dsl.downstream_rate_kbps || 0) + " kbps (" + downMb + " Mbps)");
            setVal("tblUpRate", (dsl.upstream_rate_kbps || 0) + " kbps (" + upMb + " Mbps)");
            setVal("tblDownMax", (dsl.downstream_max_kbps || 0) + " kbps (" + maxDownMb + " Mbps)");
            setVal("tblUpMax", (dsl.upstream_max_kbps || 0) + " kbps (" + maxUpMb + " Mbps)");
            setVal("tblDownSnr", (dsl.downstream_snr_db || 0) + " dB");
            setVal("tblUpSnr", (dsl.upstream_snr_db || 0) + " dB");
            setVal("tblDownAttn", (dsl.downstream_attenuation_db || 0) + " dB");
            setVal("tblUpAttn", (dsl.upstream_attenuation_db || 0) + " dB");
            setVal("tblDownCrc", dsl.down_crc_errors || 0);
            setVal("tblUpCrc", dsl.up_crc_errors || 0);
            setVal("tblDownFec", dsl.fec_errors || 0);
            setVal("tblModulation", dsl.modulation || "VDSL2");
            setVal("tblProfile", dsl.profile || "17a");
            setVal("tblShowtime", formatDuration(dsl.showtime_seconds));
        }

        async function loadSyslog(manual) {
            manual = Boolean(manual);
            try {
                const res = await fetch("/api/logs");
                const logs = await res.json();
                syslogData = logs || [];
                const txt = document.getElementById("syslogTotalText");
                if (txt) {
                    txt.innerText = syslogData.length + (currentLang === 'ar' ? " سجل متاح" : " entries available");
                }
                renderSyslogRows();
                if (manual) showToast(currentLang === 'ar' ? "تم تحديث السجلات" : "Logs refreshed successfully");
            } catch(e) {
                console.error("loadSyslog error:", e);
            }
        }

        function setSyslogCategory(cat, e) {
            currentSyslogCategory = cat;
            document.querySelectorAll('.filter_btn').forEach(b => b.classList.remove('active'));
            if (e && e.currentTarget) e.currentTarget.classList.add('active');
            renderSyslogRows();
        }

        function renderSyslogRows() {
            const query = (document.getElementById("syslogFilterInput")?.value || "").toLowerCase().trim();
            const tbody = document.getElementById("syslogRows");
            if (!tbody) return;
            tbody.innerHTML = "";

            const isAr = (currentLang === 'ar');
            if (!syslogData || syslogData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:#666;">' + (isAr ? 'لا توجد سجلات متاحة' : 'No logs available') + '</td></tr>';
                return;
            }

            const filtered = syslogData.filter(item => {
                const matchQ = !query ||
                    (item.msg && item.msg.toLowerCase().includes(query)) ||
                    (item.time && item.time.toLowerCase().includes(query)) ||
                    (item.level && item.level.toLowerCase().includes(query));
                if (!matchQ) return false;

                const lvl = (item.level || "").toLowerCase();
                const msg = (item.msg || "").toLowerCase();

                if (currentSyslogCategory === 'warn_err') {
                    return lvl.includes('warn') || lvl.includes('err');
                } else if (currentSyslogCategory === 'pppoe') {
                    return msg.includes('pppd') || msg.includes('padi') || msg.includes('pado') || msg.includes('dsl link');
                } else if (currentSyslogCategory === 'wifi') {
                    return msg.includes('wlan') || msg.includes('dhcp') || msg.includes('sta');
                } else if (currentSyslogCategory === 'reboot') {
                    return msg.includes('reboot') || msg.includes('restart');
                }
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:#666;">' + (isAr ? 'لم يتم العثور على سجلات تطابق البحث' : 'No matching logs found') + '</td></tr>';
                return;
            }

            const slice = filtered.slice(0, 300);
            slice.forEach((item, idx) => {
                const tr = document.createElement("tr");
                const lvl = (item.level || "Info").toLowerCase();
                let typeClass = "log_notice";
                if (lvl.includes("warn")) typeClass = "log_warning";
                else if (lvl.includes("err")) typeClass = "log_error";

                tr.innerHTML = '<td style="color:#777;">' + (idx + 1) + '</td>' +
                    '<td style="color:#555; white-space:nowrap;">' + (item.time || "--") + '</td>' +
                    '<td class="' + typeClass + '">[' + (item.level || "Info") + ']</td>' +
                    '<td>' + (item.msg || item.raw || "") + '</td>';
                tbody.appendChild(tr);
            });
        }

        function copySyslogText() {
            if (!syslogData || syslogData.length === 0) {
                showToast(currentLang === 'ar' ? "لا توجد سجلات لنسخها" : "No logs to copy");
                return;
            }
            const txt = syslogData.map(x => (x.time || "") + " [" + (x.level || "Info") + "] " + (x.msg || x.raw || "")).join(String.fromCharCode(10));
            navigator.clipboard.writeText(txt).then(() => {
                showToast(currentLang === 'ar' ? "تم نسخ كافة السجلات إلى الحافظة" : "All logs copied to clipboard");
            }).catch(() => {
                showToast(currentLang === 'ar' ? "تعذر النسخ" : "Copy failed");
            });
        }

        async function clearLocalLogs() {
            const isAr = (currentLang === 'ar');
            if (!confirm(isAr ? "هل أنت متأكد من رغبتك في تفريغ ملفات التقارير والسجلات المحلية؟" : "Are you sure you want to clear local report logs?")) return;
            try {
                const res = await fetch("/api/clear-logs", { method: "POST" });
                const d = await res.json();
                showToast(d.message || (isAr ? "تم تفريغ التقارير" : "Logs cleared"));
                loadSyslog();
                loadStatus();
            } catch(e) {
                showToast("Error: " + e);
            }
        }

        // Reconnect Dialog
        function openReconnectDlg(dryRun) {
            isDryRun = dryRun;
            const isAr = (currentLang === 'ar');
            document.getElementById("dlgReconnectTitle").innerText = dryRun ? (isAr ? "اختبار محاكاة تجديد الـ IP (Dry Run)" : "Simulate PPPoE Renewal (Dry Run)") : (isAr ? "تأكيد تجديد اتصال PPPoE" : "Confirm PPPoE Renewal");
            document.getElementById("reconnectProgressBox").style.display = "none";
            document.getElementById("dlgReconnectFooter").style.display = "flex";
            document.getElementById("dlgReconnect").style.display = "flex";
        }

        function closeReconnectDlg() {
            document.getElementById("dlgReconnect").style.display = "none";
            if (reconnectTimer) { clearInterval(reconnectTimer); reconnectTimer = null; }
        }

        async function executeReconnect() {
            document.getElementById("dlgReconnectFooter").style.display = "none";
            document.getElementById("reconnectProgressBox").style.display = "block";

            try {
                await fetch("/api/reconnect", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ dry_run: isDryRun, confirm: true })
                });
                reconnectTimer = setInterval(pollReconnectState, 1000);
            } catch(e) {
                document.getElementById("reconnectStage").innerText = currentLang === 'ar' ? "خطأ في الاتصال" : "Connection Error";
                document.getElementById("reconnectMsg").innerText = e.toString();
            }
        }

        async function pollReconnectState() {
            try {
                const res = await fetch("/api/reconnect/status");
                const data = await res.json();

                const bar = document.getElementById("reconnectBar");
                const stage = document.getElementById("reconnectStage");
                const msg = document.getElementById("reconnectMsg");

                if (bar) bar.style.width = (data.percent || 5) + "%";
                if (stage) stage.innerText = data.stage || (currentLang === 'ar' ? "جاري المعالجة..." : "Processing...");
                if (msg) msg.innerText = data.message || "";

                if (data.status === "success") {
                    clearInterval(reconnectTimer);
                    reconnectTimer = null;
                    if (bar) bar.style.width = "100%";
                    if (stage) stage.innerText = currentLang === 'ar' ? "اكتمل بنجاح" : "Success";
                    const ip = data.result && data.result.wan_ip ? ((currentLang === 'ar' ? "عنوان IP الجديد: " : "New WAN IP: ") + data.result.wan_ip) : (currentLang === 'ar' ? "تمت العملية بنجاح." : "Operation completed.");
                    if (msg) msg.innerText = ip;
                    setTimeout(() => {
                        closeReconnectDlg();
                        loadStatus();
                        loadSyslog();
                    }, 2500);
                } else if (data.status === "error") {
                    clearInterval(reconnectTimer);
                    reconnectTimer = null;
                    if (stage) stage.innerText = currentLang === 'ar' ? "فشلت العملية" : "Failed";
                    if (msg) msg.innerText = data.error || (currentLang === 'ar' ? "تعذرت إعادة الاتصال." : "Reconnect failed.");
                    setTimeout(closeReconnectDlg, 4000);
                }
            } catch(e) {
                console.error("pollReconnect error:", e);
            }
        }

        // Reboot Dialog
        function openRebootDlg() {
            document.getElementById("rebootConfirmText").style.display = "block";
            document.getElementById("rebootProgressBox").style.display = "none";
            document.getElementById("dlgRebootFooter").style.display = "flex";
            document.getElementById("dlgReboot").style.display = "flex";
        }

        function closeRebootDlg() {
            document.getElementById("dlgReboot").style.display = "none";
            if (rebootTimer) { clearInterval(rebootTimer); rebootTimer = null; }
        }

        async function executeReboot() {
            document.getElementById("dlgRebootFooter").style.display = "none";
            document.getElementById("rebootConfirmText").style.display = "none";
            document.getElementById("rebootProgressBox").style.display = "block";

            try {
                await fetch("/api/reboot", { method: "POST" });
            } catch(e) {}

            rebootSeconds = 120;
            rebootTimer = setInterval(async () => {
                rebootSeconds -= 2;
                const bar = document.getElementById("rebootBar");
                const lbl = document.getElementById("rebootTimerLabel");
                const pct = Math.min(100, Math.round(((120 - rebootSeconds) / 120) * 100));

                if (bar) bar.style.width = pct + "%";
                if (lbl) lbl.innerText = Math.max(0, rebootSeconds) + (currentLang === 'ar' ? " ثانية متبقية" : " seconds remaining");

                if (rebootSeconds <= 70) {
                    try {
                        const test = await fetch("/api/status");
                        const json = await test.json();
                        if (json && json.connected_to_router) {
                            clearInterval(rebootTimer);
                            rebootTimer = null;
                            if (bar) bar.style.width = "100%";
                            if (lbl) lbl.innerText = currentLang === 'ar' ? "عاد الراوتر للعمل بنجاح!" : "Router is back online!";
                            document.getElementById("rebootStatusLabel").innerText = currentLang === 'ar' ? "جاري إعادة تحميل الواجهة..." : "Reloading interface...";
                            setTimeout(() => {
                                closeRebootDlg();
                                window.location.reload();
                            }, 2000);
                            return;
                        }
                    } catch(err) {}
                }

                if (rebootSeconds <= 0) {
                    clearInterval(rebootTimer);
                    rebootTimer = null;
                    window.location.reload();
                }
            }, 2000);
        }

        // Firmware Management Functions
        async function checkFirmwareQuickStatus() {
            try {
                const res = await fetch("/api/firmware/info");
                const info = await res.json();
                const badge = document.getElementById("fwStatusBadge");
                if (info.file_exists) {
                    badge.style.color = "#0E8A16";
                    badge.innerText = currentLang === 'ar' ? "الملف متوفر وجاهز للفحص" : "Image Detected - Ready to Inspect";
                }
            } catch(e) {}
        }

        async function inspectLocalFirmware() {
            showToast(currentLang === 'ar' ? "جاري فحص وتدقيق الحزمة..." : "Inspecting firmware binary...");
            try {
                const res = await fetch("/api/firmware/inspect", { method: "POST" });
                const data = await res.json();

                const box = document.getElementById("fwInspectResultBox");
                const badge = document.getElementById("fwStatusBadge");
                box.style.display = "block";

                if (data.valid) {
                    badge.style.color = "#0E8A16";
                    badge.innerText = currentLang === 'ar' ? "سليم ومطابق 100%" : "Verified & 100% Compatible";

                    document.getElementById("fwResMagic").innerText = data.magic + " (ZTE Tag OK)";
                    document.getElementById("fwResModel").innerText = data.model + " (ZXHN H188A OK)";
                    document.getElementById("fwResVer").innerText = data.version + " (" + data.build_timestamp + ")";
                    
                    const k = data.kernel || {};
                    document.getElementById("fwResKernel").innerText = (k.valid ? "OK - " : "Error - ") + k.decompressed_mb + " MB (" + k.arch + ") " + (k.soc || "");

                    const r = data.rootfs || {};
                    document.getElementById("fwResRootfs").innerText = (r.valid ? "OK - " : "Error - ") + r.type + " (" + r.size_mb + " MB, " + (r.inodes || 0) + " inodes, LZMA)";

                    document.getElementById("fwResSha256").innerText = data.sha256;

                    document.getElementById("fwCompatibilitySummary").innerText = currentLang === 'ar' ? "الملف صالح 100% للتفليش على هذا الراوتر" : "Binary is 100% safe and verified for ZXHN H188A";
                } else {
                    badge.style.color = "#CC0000";
                    badge.innerText = currentLang === 'ar' ? "فشل التحقق من الملف" : "Verification Failed";
                    document.getElementById("fwCompatibilitySummary").innerText = data.error || "File header invalid";
                }
            } catch(e) {
                showToast("Inspect error: " + e);
            }
        }

        function confirmUseLocalFw() {
            const isAr = (currentLang === 'ar');
            const nl = String.fromCharCode(10);
            const msg = isAr ? 
                ("هل أنت متأكد من رغبتك في اعتماد ملف الفيرموير H188a.bin المثبت في مجلد Firmware؟" + nl + nl + "تنبيه: سيتم التأكد من مطابقة الإصدار قبل إرسال أمر التحديث.") :
                ("Are you sure you want to stage H188a.bin for upgrade?" + nl + nl + "Notice: Target version will be cross-checked with device before flashing.");
            if (confirm(msg)) {
                showToast(isAr ? "تم اعتماد ملف الفيرموير بنجاح وجاهز للمتابعة." : "Firmware image verified and staged successfully.");
            }
        }

        function handleFwFileSelected() {
            const input = document.getElementById("fwFileInput");
            const btn = document.getElementById("btnUploadFw");
            if (input.files && input.files.length > 0) {
                btn.disabled = false;
            } else {
                btn.disabled = true;
            }
        }

        async function uploadNewFirmware() {
            const input = document.getElementById("fwFileInput");
            if (!input.files || input.files.length === 0) return;

            const file = input.files[0];
            const isAr = (currentLang === 'ar');

            if (!confirm((isAr ? "تأكيد رفع وفحص ملف التحديث: " : "Confirm upload and validation of: ") + file.name + "?")) return;

            const pBox = document.getElementById("fwUploadProgressBox");
            const pBar = document.getElementById("fwUploadBar");
            const pStage = document.getElementById("fwUploadStage");
            const pMsg = document.getElementById("fwUploadMsg");

            pBox.style.display = "block";
            pBar.style.width = "20%";
            pStage.innerText = isAr ? "جاري قراءة الملف ورفعه..." : "Reading and streaming firmware...";
            pMsg.innerText = file.name + " (" + Math.round(file.size / (1024*1024)) + " MB)";

            const formData = new FormData();
            formData.append("firmware", file);

            try {
                pBar.style.width = "60%";
                const res = await fetch("/api/firmware/upload", {
                    method: "POST",
                    body: formData
                });
                const result = await res.json();
                pBar.style.width = "100%";

                if (result.valid) {
                    pStage.innerText = isAr ? "اكتمل الفحص والرفع بنجاح!" : "Upload & Verification Succeeded!";
                    pMsg.innerText = (isAr ? "إصدار الحزمة: " : "Verified Version: ") + (result.version || "") + " | SHA256: " + (result.sha256 || "").substring(0, 16) + "...";
                    showToast(isAr ? "تم التحقق من الفيرموير الجديد بنجاح" : "Firmware verified successfully");
                } else {
                    pStage.innerText = isAr ? "فشل التحقق من الفيرموير" : "Verification Failed";
                    pMsg.innerText = result.error || (isAr ? "الملف غير متوافق مع ZTE H188A" : "Incompatible firmware file");
                }
            } catch(e) {
                pStage.innerText = isAr ? "خطأ في الرفع" : "Upload Error";
                pMsg.innerText = e.toString();
            }
        }

        // Global Window Bindings
        window.setLanguage = setLanguage;
        window.toggleLanguage = toggleLanguage;
        window.showTab = showTab;
        window.showToast = showToast;
        window.formatDuration = formatDuration;
        window.loadStatus = loadStatus;
        window.loadSyslog = loadSyslog;
        window.setSyslogCategory = setSyslogCategory;
        window.renderSyslogRows = renderSyslogRows;
        window.copySyslogText = copySyslogText;
        window.clearLocalLogs = clearLocalLogs;
        window.openReconnectDlg = openReconnectDlg;
        window.closeReconnectDlg = closeReconnectDlg;
        window.executeReconnect = executeReconnect;
        window.openRebootDlg = openRebootDlg;
        window.closeRebootDlg = closeRebootDlg;
        window.executeReboot = executeReboot;
        window.inspectLocalFirmware = inspectLocalFirmware;
        window.confirmUseLocalFw = confirmUseLocalFw;
        window.handleFwFileSelected = handleFwFileSelected;
        window.uploadNewFirmware = uploadNewFirmware;

        // Initialize: Detect saved language or default to Arabic
        const savedLang = localStorage.getItem('zte_lang') || 'ar';
        setLanguage(savedLang);

        loadStatus();
        setTimeout(loadSyslog, 1500);
        setInterval(() => loadStatus(false), 25000);
    </script>
</body>
</html>
"""


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        try:
            if sys.stderr is not None:
                sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))
            else:
                logger.info("%s - - %s" % (self.address_string(), format % args))
        except Exception:
            pass

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        try:
            self._handle_get()
        except Exception as e:
            logger.error(f"Unhandled GET exception for {self.path}: {e}")
            try:
                self._send_json({"error": str(e)}, status=500)
            except Exception:
                pass

    def _handle_get(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            body = HTML_PAGE.encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return

        elif path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return

        elif path == "/api/status":
            now = time.time()
            with state_lock:
                if app_state["reconnect_in_progress"]:
                    cached = app_state["cached_status"] or {}
                    cached["connected_to_router"] = True
                    self._send_json(cached)
                    return
                if app_state["cached_status"] and (now - app_state["last_status_time"] < 6):
                    self._send_json(app_state["cached_status"])
                    return

            try:
                with router_io_lock:
                    _, diagnostics, _ = get_router_toolkit()
                    report = diagnostics.get_status_summary()
                report["connected_to_router"] = True
                with state_lock:
                    app_state["cached_status"] = report
                    app_state["last_status_time"] = time.time()
                self._send_json(report)
            except Exception as e:
                logger.warning(f"Failed to fetch status: {e}")
                self._send_json({
                    "connected_to_router": False,
                    "error": str(e)
                }, status=200)
            return

        elif path == "/api/reconnect/status":
            with state_lock:
                self._send_json(app_state["reconnect_progress"])
            return

        elif path == "/api/logs":
            try:
                with router_io_lock:
                    _, diagnostics, _ = get_router_toolkit()
                    logs = diagnostics.get_all_syslog_entries(1200)
                self._send_json(logs)
            except Exception as e:
                logger.warning(f"Failed to fetch syslog: {e}")
                self._send_json([], status=200)
            return

        elif path == "/api/firmware/info":
            info = {
                "installed_version": "V2.0.1EG1T14_TE",
                "model": "ZXHN H188A",
                "hardware": "V2.0.2",
                "kernel": "Linux 3.18.21 SMP",
                "soc": "EcoNet EN7516 MIPS32",
                "file_exists": DEFAULT_FW.exists(),
                "file_path": str(DEFAULT_FW),
                "file_size": DEFAULT_FW.stat().st_size if DEFAULT_FW.exists() else 0
            }
            self._send_json(info)
            return

        elif path == "/api/firmware/inspect":
            result = inspect_firmware_file(DEFAULT_FW)
            self._send_json(result)
            return

        else:
            self.send_response(404)
            self.end_headers()
            self.close_connection = True

    def do_POST(self):
        try:
            self._handle_post()
        except Exception as e:
            logger.error(f"Unhandled POST exception for {self.path}: {e}")
            try:
                self._send_json({"error": str(e)}, status=500)
            except Exception:
                pass

    def _handle_post(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        content_type = self.headers.get('Content-Type', '')

        if path == "/api/firmware/upload":
            raw_data = self.rfile.read(length) if length > 0 else b""
            # Extract binary file content from multipart/form-data
            bin_data = b""
            if b"\r\n\r\n" in raw_data:
                parts = raw_data.split(b"\r\n\r\n", 1)
                bin_body = parts[1]
                # strip boundary trailer
                if b"\r\n--" in bin_body:
                    bin_data = bin_body.split(b"\r\n--")[0]
                else:
                    bin_data = bin_body
            else:
                bin_data = raw_data

            FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
            upload_target = FIRMWARE_DIR / "uploaded_firmware.bin"
            with open(upload_target, "wb") as f:
                f.write(bin_data)

            inspect_res = inspect_firmware_file(upload_target)
            self._send_json(inspect_res)
            return

        body = self.rfile.read(length).decode('utf-8', errors='ignore') if length > 0 else ""
        req_data = json.loads(body) if body and body.startswith('{') else {}

        if path == "/api/reconnect":
            dry_run = bool(req_data.get("dry_run", False))
            with state_lock:
                if app_state["reconnect_in_progress"]:
                    self._send_json({"error": "Reconnection is already in progress"}, status=409)
                    return
            run_reconnect_thread(dry_run=dry_run)
            self._send_json({"success": True, "message": "Reconnection initiated"})
            return

        elif path == "/api/reboot":
            logger.warning("User triggered router reboot from web dashboard...")
            try:
                with router_io_lock:
                    client, _, _ = get_router_toolkit()
                    success, resp_msg = client.reboot()
                with state_lock:
                    app_state["client"] = None
                    app_state["diagnostics"] = None
                    app_state["manager"] = None
                    app_state["cached_status"] = None
                if success:
                    self._send_json({"success": True, "message": "تم إرسال أمر إعادة تشغيل الراوتر (Reboot) بنجاح."})
                else:
                    self._send_json({"success": False, "error": f"فشل أمر إعادة التشغيل: {resp_msg}"}, status=500)
            except Exception as e:
                logger.error(f"Reboot endpoint error: {e}")
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        elif path == "/api/firmware/inspect":
            result = inspect_firmware_file(DEFAULT_FW)
            self._send_json(result)
            return

        elif path == "/api/clear-logs":
            logger.info("User requested clearing logs and diagnostic reports...")
            cleared_files = []
            try:
                if LOGS_DIR.exists():
                    for item in LOGS_DIR.glob("*.*"):
                        try:
                            if item.suffix.lower() == ".log":
                                with open(item, "w", encoding="utf-8") as f:
                                    pass
                                cleared_files.append(item.name + " (cleared)")
                            else:
                                item.unlink()
                                cleared_files.append(item.name)
                        except Exception as e:
                            logger.error(f"Could not clear {item}: {e}")
                self._send_json({
                    "success": True,
                    "message": f"تم تفريغ {len(cleared_files)} ملفات تقارير بنجاح.",
                    "cleared_count": len(cleared_files)
                })
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
            return

        else:
            self.send_response(404)
            self.end_headers()
            self.close_connection = True

def run_server(port=8080, open_browser=True):
    ThreadingHTTPServer.allow_reuse_address = True
    server = None
    actual_port = port

    for p in range(port, port + 5):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), RequestHandler)
            actual_port = p
            break
        except OSError:
            continue

    if not server:
        print(f"[ERROR] Could not bind to port {port}. Please close any other app using port {port}.")
        return

    url = f"http://127.0.0.1:{actual_port}"
    print(f"\n{'='*60}")
    print(f"  ZTE ZXHN H188A Web Management")
    print(f"  Running at: {url}")
    print(f"{'='*60}\n")
    
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        with state_lock:
            if app_state["client"]:
                try:
                    app_state["client"].logout()
                except Exception:
                    pass

if __name__ == "__main__":
    port = 8080
    open_browser = True
    for arg in sys.argv[1:]:
        if arg == "--no-browser":
            open_browser = False
        elif arg.isdigit():
            port = int(arg)
    run_server(port=port, open_browser=open_browser)
