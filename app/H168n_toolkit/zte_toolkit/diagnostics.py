import re
from .client import H168NClient


class H168NDiagnostics:
    """Adapter discovery and live Wi-Fi/router status queries for ZXHN H168N."""

    def __init__(self, client=None):
        self.client = client or H168NClient()

    def detect_adapters(self):
        ok, out, err = self.client._run(["detect", "--target", self.client.target_ip])
        adapters = []
        for line in out.splitlines():
            m = re.match(r"^\s*\[(OK|--)\]\s+(.+?)\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(.+)$", line)
            if m:
                status, name, ip, detail = m.groups()
                title = detail.replace("Title:", "").strip() if status == "OK" else detail.strip()
                adapters.append({
                    "ok": status == "OK",
                    "adapter": name.strip(),
                    "ip": ip.strip(),
                    "title": title,
                    "is_h168n": "H168N" in title,
                })
        return {"success": ok, "adapters": adapters, "raw": out, "error": err}

    def get_info(self):
        args = ["info", "--target", self.client.target_ip]
        if self.client.bind_ip:
            args += ["--bind-ip", self.client.bind_ip]
        ok, out, err = self.client._run(args)
        return {"success": ok, "raw": out, "error": err}
