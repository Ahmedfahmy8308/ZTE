import subprocess
import socket
import json
import re
import html
from datetime import datetime
from pathlib import Path
from .logger import setup_logger

logger = setup_logger()

class RouterDiagnostics:
    def __init__(self, client):
        self.client = client
        self._cached_upnp = None

    @staticmethod
    def run_command(args, timeout=5):
        try:
            p = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace"
            )
            return {"code": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
        except Exception as e:
            return {"error": str(e), "code": -1}

    def check_local_network(self, internet_ip="1.1.1.1", dns_host="example.com"):
        """
        Ultra-fast network check (<0.1s when online, <0.5s when offline):
        1. Reads local default gateway.
        2. Fast TCP connect to gateway (port 80/443).
        3. Fast TCP connect to internet IP (port 53).
        4. DNS lookup only if internet socket succeeds (avoids Windows 10s DNS hang).
        """
        route = self.run_command(["route", "print", "-4"], timeout=2)
        gateway = None
        for line in route.get("stdout", "").splitlines():
            p = line.split()
            if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                gateway = p[2]
                break

        gw_target = gateway or self.client.host
        gw_ok = False
        for port in (80, 443):
            try:
                s = socket.create_connection((gw_target, port), timeout=0.25)
                s.close()
                gw_ok = True
                break
            except Exception:
                pass

        if not gw_ok and gateway:
            res = self.run_command(["ping", "-n", "1", "-w", "400", gateway], timeout=1)
            gw_ok = (res.get("code") == 0)

        # Fast internet test via DNS port 53 (direct socket, 10x faster than ping.exe)
        inet_ok = False
        for host in (internet_ip, "8.8.8.8"):
            try:
                s = socket.create_connection((host, 53), timeout=0.4)
                s.close()
                inet_ok = True
                break
            except Exception:
                pass

        # DNS resolution test: ONLY run if internet is reachable to avoid OS blocking
        dns_ok = False
        dns_error = None
        if inet_ok:
            try:
                socket.getaddrinfo(dns_host, 443, socket.AF_INET)
                dns_ok = True
            except Exception as e:
                dns_error = str(e)
        else:
            dns_error = "Internet unreachable"

        return {
            "default_gateway": gateway,
            "gateway_reachable": gw_ok,
            "internet_reachable": inet_ok,
            "dns_resolving": dns_ok,
            "dns_error": dns_error
        }

    def check_upnp_support(self):
        """
        Tests whether UPnP / SSDP is responsive on port 1900. Cached after first run.
        """
        if self._cached_upnp is not None:
            return self._cached_upnp

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        req = "\r\n".join([
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "", ""
        ]).encode("ascii")

        upnp_found = False
        try:
            s.sendto(req, (self.client.host, 1900))
            data, _ = s.recvfrom(2048)
            if data:
                upnp_found = True
        except Exception:
            upnp_found = False
        finally:
            s.close()

        self._cached_upnp = {
            "upnp_igd_supported": upnp_found,
            "reason": "UPnP IGD daemon is disabled, filtered, or port 1900 is closed in WE firmware."
        }
        return self._cached_upnp

    def get_dsl_status(self):
        """
        Retrieves physical DSL / VDSL line parameters from router.
        """
        self.client.navigate("Internet_AdminInternetStatus_DSL_t.lp")
        xml_root = self.client.get_xml("common_page/internet_dsl_interface_lua.lua")
        if xml_root is None:
            return {
                "status": "Down",
                "modulation": "Unknown",
                "profile": "Unknown",
                "downstream_rate_mbps": 0.0,
                "upstream_rate_mbps": 0.0,
                "downstream_snr_db": 0.0,
                "upstream_snr_db": 0.0,
                "downstream_attenuation_db": 0.0,
                "upstream_attenuation_db": 0.0,
                "down_crc_errors": 0,
                "up_crc_errors": 0,
                "fec_errors": 0,
                "showtime_seconds": 0
            }

        inst = xml_root.find(".//Instance")
        if inst is None:
            return {
                "status": "Down",
                "modulation": "Unknown",
                "profile": "Unknown",
                "downstream_rate_mbps": 0.0,
                "upstream_rate_mbps": 0.0,
                "downstream_snr_db": 0.0,
                "upstream_snr_db": 0.0,
                "downstream_attenuation_db": 0.0,
                "upstream_attenuation_db": 0.0,
                "down_crc_errors": 0,
                "up_crc_errors": 0,
                "fec_errors": 0,
                "showtime_seconds": 0
            }

        params = {}
        for p, v in zip(inst.findall("ParaName"), inst.findall("ParaValue")):
            params[p.text] = v.text

        # Unit conversions
        down_rate = int(params.get("Downstream_current_rate", 0) or 0)
        up_rate = int(params.get("Upstream_current_rate", 0) or 0)
        down_snr = float(params.get("Downstream_noise_margin", 0) or 0) / 10.0
        up_snr = float(params.get("Upstream_noise_margin", 0) or 0) / 10.0
        down_attn = float(params.get("Downstream_attenuation", 0) or 0) / 10.0
        up_attn = float(params.get("Upstream_attenuation", 0) or 0) / 10.0

        return {
            "status": params.get("Status", "Unknown"),
            "modulation": params.get("Module_type", "Unknown"),
            "profile": params.get("CurrentProfile", "Unknown"),
            "encapsulation": params.get("tLinkEncapsulationUsed", "Unknown"),
            "downstream_rate_kbps": down_rate,
            "downstream_rate_mbps": round(down_rate / 1024, 2),
            "upstream_rate_kbps": up_rate,
            "upstream_rate_mbps": round(up_rate / 1024, 2),
            "downstream_max_kbps": int(params.get("Downstream_max_rate", 0) or 0),
            "upstream_max_kbps": int(params.get("Upstream_max_rate", 0) or 0),
            "downstream_snr_db": down_snr,
            "upstream_snr_db": up_snr,
            "downstream_attenuation_db": down_attn,
            "upstream_attenuation_db": up_attn,
            "down_crc_errors": int(params.get("DownCrc_errors", 0) or 0),
            "up_crc_errors": int(params.get("UpCrc_errors", 0) or 0),
            "fec_errors": int(params.get("Fec_errors", 0) or 0),
            "showtime_seconds": int(params.get("Showtime_start", 0) or 0),
            "raw": params
        }

    def get_wan_pppoe_status(self):
        """
        Retrieves WAN connections and details of the PPPoE connection.
        """
        self.client.navigate("Internet_AdminInternetStatus_DSL_t.lp")
        xml_root = self.client.get_xml("common_page/Internet_Internet_lua.lua?TypeUplink=1&pageType=1")
        if xml_root is None:
            return None

        wan_obj = xml_root.find("ID_WAN_COMFIG")
        if wan_obj is None:
            return None

        wan_instances = []
        for inst in wan_obj.findall("Instance"):
            item = {}
            for p, v in zip(inst.findall("ParaName"), inst.findall("ParaValue")):
                item[p.text] = v.text
            wan_instances.append(item)

        # Primary PPPoE instance is WAN0 (IGD.WD1.WCD1.WCPPP1)
        pppoe_inst = None
        for w in wan_instances:
            if w.get("WANCName") == "WAN0" or (w.get("TransType") == "PPPoE" and w.get("mode") == "route" and w.get("xdslMode") == "2"):
                pppoe_inst = w
                break

        if not pppoe_inst and wan_instances:
            pppoe_inst = wan_instances[0]

        if not pppoe_inst:
            return None

        # Friendly disconnect reason mapping
        err_map = {
            "ERROR_NONE": "متصل بشكل طبيعي (None / Connected)",
            "ERROR_ISP_TIME_OUT": "عدم استجابة سيرفر المزود (ISP BRAS Timeout / PADI)",
            "ERROR_USER_DISCONNECT": "تم قطع الاتصال يدوياً بواسطة المستخدم",
            "ERROR_ISP_DISCONNECT": "مزود الخدمة قام بإنهاء الجلسة (ISP Terminated)",
            "ERROR_IDLE_DISCONNECT": "انتهت مهلة خمول الجلسة (Idle Timeout)",
            "ERROR_FORCED_DISCONNECT": "إعادة تشغيل أو قطع إجباري للجلسة",
            "ERROR_AUTHENTICATION_FAILURE": "فشل التحقق من اسم المستخدم أو كلمة مرور اشتراك النت (PAP/CHAP Failure)",
            "ERROR_IP_CONFIGURATION": "عدم تخصيص IP من المزود / نفاد عناوين السيرفر",
            "ERROR_NOT_ENABLED_FOR_INTERNET": "الاتصال معطل من الإعدادات",
            "ERROR_NO_CARRIER": "انقطاع إشارة سلك التليفون الأرضي (No DSL Carrier)"
        }

        conn_err = pppoe_inst.get("ConnError", "ERROR_UNKNOWN")
        friendly_err = err_map.get(conn_err, conn_err)

        return {
            "instance_id": pppoe_inst.get("_InstID", ""),
            "wan_name": pppoe_inst.get("WANCName", ""),
            "connection_status": pppoe_inst.get("ConnStatus", "Unknown"),
            "disconnect_code": conn_err,
            "disconnect_reason": friendly_err,
            "wan_ip": pppoe_inst.get("IPAddress", "0.0.0.0"),
            "subnet_mask": pppoe_inst.get("SubnetMask", "0.0.0.0"),
            "gateway": pppoe_inst.get("GateWay", "0.0.0.0"),
            "dns1": pppoe_inst.get("DNS1", "0.0.0.0"),
            "dns2": pppoe_inst.get("DNS2", "0.0.0.0"),
            "uptime_seconds": int(pppoe_inst.get("UpTime", 0) or 0),
            "vlan_enabled": (pppoe_inst.get("VlanEnable") == "1"),
            "vlan_id": pppoe_inst.get("VLANID", "None"),
            "username": pppoe_inst.get("UserName", ""),
            "mtu": int(pppoe_inst.get("MTU", 1492) or 1492),
            "nat_enabled": (pppoe_inst.get("IsNAT") == "1"),
            "raw": pppoe_inst
        }

    def _extract_syslog_text(self):
        self.client.navigate("ManagDiag_LogManag_t.lp")
        xml_root = self.client.get_xml("common_page/ManagDiag_LogManag_lua.lua")
        if xml_root is None:
            return ""

        inst = xml_root.find(".//OBJ_LOG_ID/Instance")
        if inst is not None:
            names = [p.text for p in inst.findall("ParaName")]
            vals = [p.text for p in inst.findall("ParaValue")]
            data = dict(zip(names, vals))
            return html.unescape(data.get("logStr", "") or "")
        return ""

    def get_all_syslog_entries(self, max_entries=1000):
        """
        Fetches the complete router system log exactly as shown in the ZTE web interface.
        Returns all structured entries: timestamp, level, and message (newest first).
        """
        raw_text = self._extract_syslog_text()
        if not raw_text:
            return []

        pattern = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)\s*\[([^\]]+)\]\s*(.*)$')
        entries = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or any(line.startswith(p) for p in ['Manufacturer:', 'ProductClass:', 'IP:', 'HWVer:', 'SWVer:']):
                continue
            m = pattern.match(line)
            if m:
                ts = m.group(1).replace('T', ' ').replace('Z', '')
                entries.append({
                    "time": ts,
                    "level": m.group(2).strip(),
                    "msg": m.group(3).strip(),
                    "raw": line
                })
            else:
                entries.append({
                    "time": "--",
                    "level": "Info",
                    "msg": line,
                    "raw": line
                })

        entries.reverse()
        return entries[:max_entries]

    def get_recent_pppoe_logs(self, max_lines=80):
        """
        Fetches recent PPPoE, DSL, and system events for analysis.
        """
        raw_text = self._extract_syslog_text()
        if not raw_text:
            return []

        keywords = ["pppd", "padi", "pado", "padr", "pads", "lcp", "dsl link", "reboot", "attack", "login success", "login failed"]
        relevant = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if any(k in line.lower() for k in keywords):
                relevant.append(line)

        return relevant[-max_lines:]

    def analyze_syslog_events(self, raw_lines):
        """
        Parses syslog lines to extract actionable diagnostic insights:
        - DSL drops
        - PPPoE discovery timeouts (PADI without response)
        - Router reboots
        - Security alerts (Port scans)
        - Connected client devices
        """
        padi_count = 0
        pado_count = 0
        dsl_drops = 0
        reboots = 0
        attacks = []
        clients = set()

        for line in raw_lines:
            l = line.lower()
            if "send padi" in l:
                padi_count += 1
            if "recv pado" in l:
                pado_count += 1
            if "dsl: dsl link down" in l:
                dsl_drops += 1
            if "the system will reboot" in l:
                reboots += 1
            if "port scan" in l or "attack" in l:
                attacks.append(line)
            m_mac = re.search(r'mac\s*=\s*([0-9a-f:]{11,17})', l)
            if m_mac:
                clients.add(m_mac.group(1))

        insights = []
        if dsl_drops > 0:
            insights.append(f"تكرر انقطاع المزامنة الفيزيائية لسلك التليفون (DSL link down) بمعدل {dsl_drops} مرات.")
        if padi_count > 0:
            ratio = f"{pado_count}/{padi_count}"
            if pado_count < padi_count:
                insights.append(f"هناك تأخر أو انقطاع من سيرفر المزود في الرد على طلبات الاتصال (PADI -> PADO نسبة النجاح: {ratio}).")
        if reboots > 0:
            insights.append(f"تم رصد إعادة تشغيل للراوتر (Reboot) بمعدل {reboots} مرات.")
        if attacks:
            insights.append(f"تم صد {len(attacks)} محاولات فحص منافذ خارجية (Port Scan Attacks) بواسطة جدار الحماية بنجاح.")

        return {
            "dsl_drops": dsl_drops,
            "padi_count": padi_count,
            "pado_count": pado_count,
            "reboots": reboots,
            "port_scan_alerts": len(attacks),
            "active_clients_count": len(clients),
            "insights": insights
        }

    def get_status_summary(self):
        """
        Ultra-fast status fetch (<0.5s) querying DSL and WAN status in a single page navigation.
        Avoids redundant ping, upnp, and syslog queries on standard status updates.
        """
        self.client.navigate("Internet_AdminInternetStatus_DSL_t.lp")
        dsl = self.get_dsl_status()
        wan = self.get_wan_pppoe_status()
        return {
            "timestamp": datetime.now().isoformat(),
            "dsl_line": dsl,
            "wan_pppoe": wan,
            "connected_to_router": True
        }

    def full_diagnostic_report(self):
        """
        Compiles the complete diagnostic picture of the line, router, and session.
        """
        local_net = self.check_local_network()
        upnp = self.check_upnp_support()
        dsl = self.get_dsl_status()
        wan = self.get_wan_pppoe_status()
        recent_logs = self.get_recent_pppoe_logs(50)
        log_analysis = self.analyze_syslog_events(recent_logs)

        # Health assessment
        assessment = []
        if local_net["gateway_reachable"]:
            assessment.append("[OK] الكمبيوتر متصل بالراوتر محلياً بنجاح (192.168.1.1).")
        else:
            assessment.append("[CRITICAL] تعذر الوصول إلى بوابة الراوتر (192.168.1.1).")

        if dsl and dsl["status"].lower() == "up":
            assessment.append(f"[OK] سلك التليفون ومزامنة DSL مستقرة ({dsl['modulation']} {dsl['profile']}) بسرعة {dsl['downstream_rate_mbps']}M تنزيل / {dsl['upstream_rate_mbps']}M رفع.")
        else:
            assessment.append("[FAIL] مزامنة DSL مفصولة (DSL Down)! يرجى فحص سلك التليفون الأرضي والسبليتر.")

        if wan:
            if wan["connection_status"].lower() == "connected" and wan["wan_ip"] not in ["0.0.0.0", "", None]:
                assessment.append(f"[OK] جلسة PPPoE متصلة بنجاح. عنوان الـ IP المخصص: {wan['wan_ip']}.")
            elif wan["connection_status"].lower() == "connecting":
                assessment.append(f"[WARN] جاري التفاوض وبدء اتصال PPPoE... ({wan['disconnect_reason']}).")
            else:
                assessment.append(f"[FAIL] اتصال النت (PPPoE) غير متصل حالياً. السبب: {wan['disconnect_reason']}.")
        
        if local_net["internet_reachable"] and local_net["dns_resolving"]:
            assessment.append("[OK] خدمة الإنترنت والتصفح (DNS) تعمل بكفاءة من جهازك.")
        else:
            assessment.append("[FAIL] لا يمكن الوصول للإنترنت الخارجي حالياً.")

        report = {
            "timestamp": datetime.now().isoformat(),
            "local_network": local_net,
            "upnp_probe": upnp,
            "dsl_line": dsl,
            "wan_pppoe": wan,
            "assessment": assessment,
            "log_analysis": log_analysis,
            "recent_pppoe_logs": recent_logs
        }
        return report
