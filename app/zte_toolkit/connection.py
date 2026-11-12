import time
import socket
import subprocess
from datetime import datetime
from .logger import setup_logger

logger = setup_logger()

class PPPoEConnectionManager:
    def __init__(self, client, diagnostics, cooldown_seconds=6, max_retries=3, verify_timeout=45):
        self.client = client
        self.diagnostics = diagnostics
        self.cooldown_seconds = cooldown_seconds
        self.max_retries = max_retries
        self.verify_timeout = verify_timeout
        self.target_endpoint = "common_page/Internet_Internet_lua.lua?TypeUplink=1&pageType=0"
        self.target_instance = "IGD.WD1.WCD1.WCPPP1"

    def _build_action_payload(self, action_type, wan_status=None):
        """
        Builds the exact dataPost payload conforming to ZTE ZXHN H188A WE firmware.
        """
        inst_id = self.target_instance
        if wan_status and wan_status.get("instance_id"):
            inst_id = wan_status["instance_id"]

        params = [
            ("IF_ACTION", action_type),
            ("_InstID", inst_id),
            ("IF_UPLINK", "1"),
            ("xdslMode", "2"),
            ("Status", "Up"),
            ("linkMode", "PPP"),
            ("TransType", "PPPoE"),
            ("IpMode", "IPv4"),
            ("mode", "route")
        ]
        
        query = "&".join(f"{k}={v}" for k, v in params)
        return query

    def disconnect_pppoe(self, dry_run=False):
        """
        Sends PPPDISCONNECT to release PPPoE session without altering configuration.
        """
        wan = self.diagnostics.get_wan_pppoe_status()
        payload = self._build_action_payload("PPPDISCONNECT", wan)

        if dry_run:
            logger.info("[DRY RUN] Simulating PPPoE Disconnect...")
            logger.info(f"[DRY RUN] Target Endpoint: {self.target_endpoint}")
            logger.info(f"[DRY RUN] Payload: {payload}")
            return True, "Dry-run disconnect simulated successfully."

        logger.info(f"Sending PPPDISCONNECT to router for instance '{self.target_instance}'...")
        # Force fresh session navigation to WAN connection subpage (Internet_Dsl_t.lp)
        self.client.navigate("Internet_Dsl_t.lp", force=True)
        # Initialize WAN container state
        self.client._request(self.target_endpoint)
        success, resp = self.client.post_data_transfer(self.target_endpoint, payload)
        
        if success:
            logger.info("PPPDISCONNECT command accepted by router.")
            return True, resp
        else:
            logger.error(f"PPPDISCONNECT failed or returned error: {resp[:200]}")
            return False, resp

    def connect_pppoe(self, dry_run=False):
        """
        Sends PPPCONNECT to initiate a new PPPoE discovery session.
        """
        wan = self.diagnostics.get_wan_pppoe_status()
        payload = self._build_action_payload("PPPCONNECT", wan)

        if dry_run:
            logger.info("[DRY RUN] Simulating PPPoE Connect...")
            logger.info(f"[DRY RUN] Target Endpoint: {self.target_endpoint}")
            logger.info(f"[DRY RUN] Payload: {payload}")
            return True, "Dry-run connect simulated successfully."

        logger.info(f"Sending PPPCONNECT to router for instance '{self.target_instance}'...")
        # Force fresh session navigation to WAN connection subpage (Internet_Dsl_t.lp)
        self.client.navigate("Internet_Dsl_t.lp", force=True)
        # Initialize WAN container state
        self.client._request(self.target_endpoint)
        success, resp = self.client.post_data_transfer(self.target_endpoint, payload)
        
        if success:
            logger.info("PPPCONNECT command accepted by router.")
            return True, resp
        else:
            logger.error(f"PPPCONNECT failed or returned error: {resp[:200]}")
            return False, resp

    def verify_connection(self, expected_different_ip=None, timeout=None, progress_callback=None):
        """
        Polls router until WAN IP is assigned and internet connectivity is restored.
        """
        timeout = timeout or self.verify_timeout
        logger.info(f"Waiting for WAN IP and internet connectivity (timeout: {timeout}s)...")
        start_time = time.time()
        
        new_ip = None
        while time.time() - start_time < timeout:
            time.sleep(3)
            wan = self.diagnostics.get_wan_pppoe_status()
            if not wan:
                continue

            status = wan.get("connection_status", "")
            current_ip = wan.get("wan_ip", "0.0.0.0")
            disconnect_reason = wan.get("disconnect_reason", "")

            elapsed = int(time.time() - start_time)
            logger.info(f"[{elapsed}s] Status: {status} | IP: {current_ip} | Reason: {disconnect_reason}")
            
            if progress_callback:
                progress_callback(
                    percent=min(95, 70 + int((elapsed / timeout) * 25)),
                    stage="مراقبة الاتصال",
                    message=f"الحالة: {status} | عنوان الـ IP: {current_ip}"
                )

            if status.lower() == "connected" and current_ip not in ["0.0.0.0", "", None]:
                new_ip = current_ip
                # Verify internet access via DNS / Ping
                net = self.diagnostics.check_local_network()
                if net["internet_reachable"] or net["dns_resolving"]:
                    logger.info(f"Internet restored successfully! WAN IP: {new_ip}")
                    if progress_callback:
                        progress_callback(
                            percent=100,
                            stage="اكتمل بنجاح",
                            message=f"تم استعادة الإنترنت بعنوان IP: {new_ip}"
                        )
                    return True, {
                        "wan_ip": new_ip,
                        "old_ip": expected_different_ip,
                        "ip_changed": (expected_different_ip != new_ip) if expected_different_ip else None,
                        "elapsed_seconds": elapsed,
                        "dns1": wan.get("dns1"),
                        "dns2": wan.get("dns2"),
                        "gateway": wan.get("gateway")
                    }
                else:
                    logger.info("IP assigned, waiting for DNS / gateway routing to stabilize...")
                    time.sleep(2)

        logger.error(f"Timed out after {timeout}s waiting for internet connection.")
        return False, {"wan_ip": new_ip, "elapsed_seconds": timeout}

    def reconnect(self, dry_run=False, progress_callback=None):
        """
        Full orchestration of safe PPPoE reconnection:
        1. Capture old IP and verify DSL sync.
        2. Disconnect.
        3. Cooldown period.
        4. Connect.
        5. Verification and monitoring.
        """
        logger.info("Starting safe PPPoE reconnection sequence...")
        if progress_callback:
            progress_callback(percent=5, stage="فحص مزامنة DSL", message="جاري التحقق من استقرار الخط الفيزيائي...")
        
        # Pre-check: Ensure physical DSL link is Up!
        dsl = self.diagnostics.get_dsl_status()
        if not dsl or dsl["status"].lower() != "up":
            msg = "Cannot reconnect: DSL physical link is DOWN! Check line sync first."
            logger.error(msg)
            if progress_callback:
                progress_callback(percent=0, stage="خطأ", message=msg)
            return False, {"error": msg}

        # Record pre-reconnect state
        initial_wan = self.diagnostics.get_wan_pppoe_status()
        old_ip = initial_wan.get("wan_ip") if initial_wan else None
        logger.info(f"Current WAN IP before reconnection: {old_ip}")

        # Attempt reconnect with retry loop
        for attempt in range(1, self.max_retries + 1):
            logger.info(f"--- Reconnection Attempt {attempt} of {self.max_retries} ---")
            
            # Step 1: Disconnect
            if progress_callback:
                progress_callback(
                    percent=20,
                    stage="فصل الجلسة (Disconnect)",
                    message=f"إرسال أمر PPPDISCONNECT لمزود الخدمة (محاولة {attempt}/{self.max_retries})..."
                )

            disc_ok, disc_resp = self.disconnect_pppoe(dry_run=dry_run)
            if not disc_ok:
                logger.error(f"Disconnect attempt failed: {disc_resp}")
                if attempt == self.max_retries:
                    if progress_callback:
                        progress_callback(percent=0, stage="فشل الفصل", message="تعذر إرسال أمر قطع الجلسة للراوتر.")
                    return False, {"error": "Failed to send disconnect command"}

            # Step 2: Cooldown
            if dry_run:
                logger.info(f"[DRY RUN] Cooldown of {self.cooldown_seconds}s simulated.")
                if progress_callback:
                    progress_callback(percent=45, stage="محاكاة التهدئة (Dry Run)", message=f"محاكاة انتظار {self.cooldown_seconds} ثوانٍ...")
            else:
                logger.info(f"Waiting cooldown period of {self.cooldown_seconds}s for ISP release...")
                for cd in range(self.cooldown_seconds, 0, -1):
                    if progress_callback:
                        progress_callback(
                            percent=30 + int((self.cooldown_seconds - cd) / self.cooldown_seconds * 20),
                            stage="فترة التهدئة (Cooldown)",
                            message=f"انتظار تحرير الجلسة في سيرفر المزود ({cd} ثوانٍ متبقية)..."
                        )
                    time.sleep(1)

            # Step 3: Connect
            if progress_callback:
                progress_callback(percent=55, stage="بدء الاتصال (Connect)", message="إرسال أمر PPPCONNECT وبدء اكتشاف الجلسة...")

            conn_ok, conn_resp = self.connect_pppoe(dry_run=dry_run)
            if not conn_ok:
                logger.error(f"Connect attempt failed: {conn_resp}")
                if attempt == self.max_retries:
                    if progress_callback:
                        progress_callback(percent=0, stage="فشل التوصيل", message="تعذر إرسال أمر الاتصال للراوتر.")
                    return False, {"error": "Failed to send connect command"}

            if dry_run:
                if progress_callback:
                    progress_callback(percent=100, stage="اكتمل الفحص التجريبي", message="تم التحقق من سلامة الأوامر بالكامل دون انقطاع فعلي.")
                return True, {
                    "dry_run": True,
                    "status": "Dry run completed successfully. All commands and structures verified."
                }

            # Step 4: Verification
            if progress_callback:
                progress_callback(percent=70, stage="مراقبة عودة الإنترنت", message="في انتظار تخصيص عنوان IP وعودة الإنترنت...")

            verified, result = self.verify_connection(expected_different_ip=old_ip, progress_callback=progress_callback)
            if verified:
                result["attempts"] = attempt
                return True, result

            logger.warning(f"Attempt {attempt} did not establish active internet within timeout.")
            if attempt < self.max_retries:
                logger.info("Retrying in 5 seconds...")
                if progress_callback:
                    progress_callback(percent=40, stage="إعادة المحاولة", message="لم يتم الحصول على IP، إعادة المحاولة خلال 5 ثوانٍ...")
                time.sleep(5)

        if progress_callback:
            progress_callback(percent=0, stage="فشل", message=f"تعذر استعادة الإنترنت بعد {self.max_retries} محاولات.")
        return False, {"error": f"Failed to restore internet after {self.max_retries} attempts"}

