import os
import sys
import argparse
import configparser
import json
import getpass
from datetime import datetime
from pathlib import Path

from zte_toolkit.client import ZTERouterClient
from zte_toolkit.diagnostics import RouterDiagnostics
from zte_toolkit.connection import PPPoEConnectionManager
from zte_toolkit.logger import setup_logger

logger = setup_logger()

CONFIG_PATH = Path(__file__).resolve().parent / "config.ini"
CONFIG_EXAMPLE = Path(__file__).resolve().parent / "config.example.ini"
LOGS_DIR = Path(__file__).resolve().parent / "logs"

def load_config():
    config = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        config.read(CONFIG_PATH, encoding="utf-8")
    elif CONFIG_EXAMPLE.exists():
        config.read(CONFIG_EXAMPLE, encoding="utf-8")
    return config

def get_credentials(args, config):
    # Username precedence: CLI arg -> env var -> config file -> default "admin"
    username = (
        args.user
        or os.getenv("ZTE_USER")
        or config.get("router", "username", fallback="admin")
    )
    
    # Password precedence: CLI arg -> env var -> config file -> prompt
    password = (
        args.password
        or os.getenv("ZTE_PASS")
        or config.get("router", "password", fallback="")
    )

    if not password and sys.stdin.isatty():
        print(f"Router credentials required for {username}@router:")
        password = getpass.getpass("Enter router admin password: ")

    if password:
        from zte_toolkit.logger import RedactingFormatter
        RedactingFormatter.add_secret(password)

    return username, password

def print_separator(title=""):
    if title:
        print(f"\n{'='*25} {title} {'='*25}")
    else:
        print("="*65)

def format_diagnostic_report(report):
    print_separator("تقرير تشخيص راوتر ZTE ZXHN H188A")
    print(f"وقت الفحص: {report['timestamp']}")
    
    # Assessment summary
    print("\n[ الخلاصة والتقييم الفني ]")
    for item in report["assessment"]:
        print(f"  {item}")

    # Local Network
    net = report["local_network"]
    print("\n[ 1. فحص الشبكة المحلية والاتصال بالراوتر ]")
    print(f"  Default Gateway  : {net['default_gateway']} (Ping: {'ناجح' if net['gateway_reachable'] else 'فاشل'})")
    print(f"  Internet Ping    : {'ناجح' if net['internet_reachable'] else 'فاشل'}")
    print(f"  DNS Resolution   : {'ناجح' if net['dns_resolving'] else 'فاشل (' + str(net['dns_error']) + ')'}")

    # UPnP Probe
    upnp = report["upnp_probe"]
    print("\n[ 2. نتيجة فحص UPnP / SSDP ]")
    print(f"  UPnP IGD Status  : {'مدعوم' if upnp['upnp_igd_supported'] else 'غير متاح / مغلق'}")
    print(f"  السبب            : {upnp['reason']}")

    # DSL Line
    dsl = report["dsl_line"]
    if dsl:
        print("\n[ 3. حالة خط الـ DSL الفيزيائي ]")
        print(f"  حالة المزامنة     : {dsl['status']}")
        print(f"  النوع والبروفايل  : {dsl['modulation']} (Profile: {dsl['profile']})")
        print(f"  سرعة التنزيل الفعلية: {dsl['downstream_rate_mbps']} Mbps ({dsl['downstream_rate_kbps']} Kbps)")
        print(f"  سرعة الرفع الفعلية  : {dsl['upstream_rate_mbps']} Mbps ({dsl['upstream_rate_kbps']} Kbps)")
        print(f"  أقصى سرعة للخط     : Down: {round(dsl['downstream_max_kbps']/1024, 2)} Mbps | Up: {round(dsl['upstream_max_kbps']/1024, 2)} Mbps")
        print(f"  مستوى التشويش SNR : Down: {dsl['downstream_snr_db']} dB | Up: {dsl['upstream_snr_db']} dB")
        print(f"  نسبة الفقد (Attn) : Down: {dsl['downstream_attenuation_db']} dB | Up: {dsl['upstream_attenuation_db']} dB")
        print(f"  أخطاء الخط CRC    : Down: {dsl['down_crc_errors']} | Up: {dsl['up_crc_errors']} | FEC: {dsl['fec_errors']}")
        print(f"  مدة اتصال الـ DSL : {dsl['showtime_seconds']} ثانية")
    else:
        print("\n[ 3. حالة خط الـ DSL ] : لم يتم الحصول على بيانات.")

    # WAN PPPoE
    wan = report["wan_pppoe"]
    if wan:
        print("\n[ 4. حالة جلسة الـ WAN / PPPoE ]")
        print(f"  اسم الاتصال       : {wan['wan_name']} ({wan['instance_id']})")
        print(f"  حالة الجلسة       : {wan['connection_status']}")
        print(f"  سبب الانقطاع الأخير: {wan['disconnect_reason']} ({wan['disconnect_code']})")
        print(f"  عنوان WAN IP      : {wan['wan_ip']}")
        print(f"  البوابة Gateway   : {wan['gateway']}")
        print(f"  خوادم DNS         : {wan['dns1']} , {wan['dns2']}")
        print(f"  مدة الاتصال Uptime: {wan['uptime_seconds']} ثانية")
        print(f"  إعداد الـ VLAN     : {'مفعل' if wan['vlan_enabled'] else 'معطل (Off)'}")
        print(f"  اسم مستخدم الخدمة: {wan['username']}")
    else:
        print("\n[ 4. حالة جلسة الـ WAN ] : لم يتم الحصول على بيانات.")

    # Recent Logs
    if report.get("recent_pppoe_logs"):
        print("\n[ 5. أحدث سجلات الـ PPPoE من ذاكرة الراوتر ]")
        for log in report["recent_pppoe_logs"][-10:]:
            print(f"  {log}")

    print_separator()

def main():
    parser = argparse.ArgumentParser(
        description="ZTE ZXHN H188A WAN & PPPoE Diagnostics and Management Toolkit"
    )
    parser.add_argument("--host", help="Router IP address (default: 192.168.1.1)")
    parser.add_argument("-u", "--user", help="Router admin username")
    parser.add_argument("-p", "--password", help="Router admin password")
    parser.add_argument("--diagnose", action="store_true", help="Run full WAN/DSL/PPPoE diagnostics")
    parser.add_argument("--reconnect", action="store_true", help="Perform PPPoE Reconnect")
    parser.add_argument("--dry-run", action="store_true", help="Simulate reconnect safely without sending command")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation for reconnect")
    parser.add_argument("--verbose", action="store_true", help="Verbose debug logging")

    args = parser.parse_args()
    config = load_config()

    host = args.host or config.get("router", "host", fallback="192.168.1.1")
    username, password = get_credentials(args, config)

    client = ZTERouterClient(host=host)
    diagnostics = RouterDiagnostics(client)
    manager = PPPoEConnectionManager(
        client, diagnostics,
        cooldown_seconds=config.getint("connection", "cooldown_seconds", fallback=6),
        max_retries=config.getint("connection", "max_retries", fallback=3),
        verify_timeout=config.getint("connection", "verify_timeout", fallback=45)
    )

    try:
        # Default action if none specified: diagnose
        if not args.diagnose and not args.reconnect:
            args.diagnose = True

        if args.diagnose:
            client.login(username=username, password=password)
            report = diagnostics.full_diagnostic_report()
            format_diagnostic_report(report)
            
            # Save report to logs
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = LOGS_DIR / f"diagnostic_report_{stamp}.json"
            out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"تم حفظ التقرير الكامل في: {out_file}\n")

        if args.reconnect:
            if not client.logged_in:
                client.login(username=username, password=password)

            if not args.dry_run and not args.confirm:
                print("\n[تحذير] سيتم فصل جلسة PPPoE وإعادة طلب عنوان IP جديد من مزود الخدمة.")
                ans = input("هل تريد الاستمرار بالتنفيذ الفعلي؟ (اكتب 'yes' للموافقة): ").strip().lower()
                if ans not in ["yes", "y"]:
                    print("تم إلغاء العملية بناءً على طلب المستخدم.")
                    return

            success, res = manager.reconnect(dry_run=args.dry_run)
            if success:
                if args.dry_run:
                    print("\n[نجاح] فحص المحاكاة (Dry Run) اكتمل بنجاح تام وتم التحقق من سلامة الأوامر.")
                else:
                    print(f"\n[نجاح] تمت إعادة الاتصال بنجاح!")
                    print(f"  عنوان IP الجديد : {res.get('wan_ip')}")
                    print(f"  عنوان IP السابق : {res.get('old_ip')}")
                    print(f"  هل تغير الـ IP   : {'نعم' if res.get('ip_changed') else 'لا'}")
                    print(f"  المستغرق         : {res.get('elapsed_seconds')} ثانية")
            else:
                print(f"\n[فشل] تعذرت إعادة الاتصال: {res.get('error')}")

    except Exception as e:
        logger.error(f"Execution error: {e}")
        print(f"\n[خطأ]: {e}")
    finally:
        client.logout()

if __name__ == "__main__":
    main()

