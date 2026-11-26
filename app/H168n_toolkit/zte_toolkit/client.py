import hashlib
import http.client
import http.cookiejar
import re
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

TOOLKIT_DIR = Path(__file__).resolve().parent.parent
H168N_CLI = TOOLKIT_DIR / "target" / "release" / "h168n-cli.exe"


class _TLS1BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context=None, source_ip=None):
        super().__init__(context=context)
        self.source_ip = source_ip

    def https_open(self, req):
        def _factory(host, **kwargs):
            if self.source_ip:
                kwargs["source_address"] = (self.source_ip, 0)
            return http.client.HTTPSConnection(host, context=self._context, **kwargs)
        return self.do_open(_factory, req)


def _create_tls1_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


class H168NWebClient:
    """Direct HTTPS (TLS 1.0) web session client for ZXHN H168N V3.1."""

    def __init__(self, bind_ip=None, target_ip="192.168.1.1", timeout=8):
        self.bind_ip = bind_ip
        self.target_ip = target_ip
        self.base_url = f"https://{target_ip}/"
        self.timeout = timeout
        self.ctx = _create_tls1_context()
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj),
            _TLS1BoundHTTPSHandler(context=self.ctx, source_ip=self.bind_ip),
        )
        self.logged_in = False

    def request(self, path, method="GET", data=None):
        url = urllib.parse.urljoin(self.base_url, path.lstrip("/"))
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": self.base_url,
            "X-Requested-With": "XMLHttpRequest",
        }
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8") if isinstance(data, dict) else data.encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")

    def login(self, username="admin", password=""):
        status, html = self.request("")
        if status != 200:
            return False, f"Router unreachable (HTTP {status})"
        if "Frm_Username" not in html and ("wizardcontrol" in html or "mainNavigator" in html):
            self.logged_in = True
            return True, "Already authenticated / wizard mode"

        tok_m = re.search(r'var _sessionTmpToken\s*=\s*["\']([^"\']+)["\']', html)
        if not tok_m:
            tok_m = re.search(r'_sessionTOKEN["\']?,\s*["\']([^"\']+)["\']', html)
        session_tok = tok_m.group(1) if tok_m else ""

        st_salt, salt_xml = self.request("function_module/login_module/login_page/logintoken_lua.lua")
        if st_salt != 200:
            return False, f"Failed to get login token (HTTP {st_salt})"
        m_salt = re.search(r"<ajax_response_xml_root>([^<]+)</ajax_response_xml_root>", salt_xml)
        if not m_salt:
            return False, "Invalid login token XML"
        salt = m_salt.group(1).strip()

        pw_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
        payload = {
            "action": "login",
            "Username": username,
            "Password": pw_hash,
            "Frm_Logintoken": "",
            "UserRandomNum": salt,
        }
        if session_tok:
            payload["_sessionTOKEN"] = session_tok
        _, resp = self.request("", method="POST", data=payload)
        if "Frm_Username" in resp and "login_error" in resp:
            err_m = re.search(r'var login_err_msg\s*=\s*"([^"]+)"', resp)
            msg = err_m.group(1) if err_m else "Invalid username or password"
            return False, msg
        self.logged_in = True
        return True, "Logged in successfully"

    def get_lan_dhcp_info(self):
        _, html = self.request("getpage.lua?pid=1002&nextpage=Localnet_LanMgrIpv4_DHCPBasicCfg_t.lp")
        return html


class H168NClient:
    """Python interface to the Rust h168n-cli.exe TLS 1.0 bridge & zcu-rs codec."""

    def __init__(self, bind_ip=None, target_ip="192.168.1.1"):
        self.bind_ip = bind_ip
        self.target_ip = target_ip

    def _run(self, args, timeout=15):
        if not H168N_CLI.exists():
            return False, "", f"h168n-cli.exe not found at {H168N_CLI}"
        res = subprocess.run(
            [str(H168N_CLI)] + list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return res.returncode == 0, res.stdout, res.stderr

    def set_wifi(self, ssid, password):
        args = ["set-wifi", "--ssid", ssid, "--pass", password, "--target", self.target_ip]
        if self.bind_ip:
            args += ["--bind-ip", self.bind_ip]
        return self._run(args)

    def decode_config(self, in_bin, out_xml, key=None, serial=None, mac=None):
        args = ["zcu-decode", str(in_bin), str(out_xml)]
        if key:
            args += ["--key", key]
        if serial:
            args += ["--serial", serial]
        if mac:
            args += ["--mac", mac]
        return self._run(args)

    def encode_config(self, in_xml, out_bin, payload_type=2, sig="ZXHN H168N V3.1", key=None, iv=None):
        args = ["zcu-encode", str(in_xml), str(out_bin), "--type", str(payload_type), "--sig", sig]
        if key:
            args += ["--key", key]
        if iv:
            args += ["--iv", iv]
        return self._run(args)
