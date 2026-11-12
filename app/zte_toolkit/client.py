import urllib.request
import urllib.parse
import http.cookiejar
import ssl
import hashlib
import re
import threading
import xml.etree.ElementTree as ET
from .logger import setup_logger

logger = setup_logger()

def _clean_token(tok):
    """
    Decodes JavaScript hex escapes (e.g. \\x31\\x32 -> 12) and strips invalid chars.
    Ensures safe usage without regex escape errors.
    """
    if not tok:
        return ""
    if "\\x" in tok or "\\X" in tok:
        try:
            tok = re.sub(r'\\[xX]([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), tok)
        except Exception:
            pass
    return tok.replace("\\", "").strip()

class ZTERouterClient:
    def __init__(self, host="192.168.1.1", use_https=True, timeout=8):
        self.host = host
        self.use_https = use_https
        self.proto = "https" if use_https else "http"
        self.base_url = f"{self.proto}://{self.host}/"
        self.timeout = timeout
        
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj),
            urllib.request.HTTPSHandler(context=self.ctx)
        )
        
        self.logged_in = False
        self.current_page = None
        self.session_token = None
        self.username = None
        self.password = None
        self._lock = threading.RLock()

    def _request(self, path, method="GET", data=None, headers=None):
        url = urllib.parse.urljoin(self.base_url, path.lstrip('/'))
        h = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": self.base_url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*"
        }
        if headers:
            h.update(headers)
            
        req_data = None
        if data is not None:
            if isinstance(data, dict):
                req_data = urllib.parse.urlencode(data).encode('utf-8')
            elif isinstance(data, str):
                req_data = data.encode('utf-8')
            else:
                req_data = data
            if "Content-Type" not in h:
                h["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
                
        req = urllib.request.Request(url, data=req_data, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return resp.status, body, resp.headers
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            return e.code, body, e.headers

    def login(self, username="admin", password=""):
        with self._lock:
            self.username = username
            self.password = password
            logger.info(f"Connecting to ZTE router at {self.base_url}...")
            
            # 1. Fetch index page
            status, html, _ = self._request("")
            if status != 200:
                raise ConnectionError(f"Cannot reach router at {self.base_url} (HTTP {status})")
                
            # Check if already logged in
            if "showCommonPage" in html and "loginWrapper" not in html:
                logger.info("Session already active.")
                self.logged_in = True
                m_tok = re.search(r'var _sessionTmpToken = ["\']([^"\']+)["\']', html)
                if m_tok:
                    self.session_token = _clean_token(m_tok.group(1))
                return True
                
            # Extract _sessionTOKEN
            m = re.search(r'LoginFormObj\.addParameter\("_sessionTOKEN",\s*"(\d+)"\)', html)
            if not m:
                m = re.search(r'_sessionTOKEN["\']?,\s*["\'](\d+)["\']', html)
            if not m:
                m = re.search(r'var _sessionTmpToken = ["\']([^"\']+)["\']', html)
                
            if not m:
                raise RuntimeError("Could not find session token in router index page.")
            self.session_token = _clean_token(m.group(1))
            
            # 2. Fetch login salt
            status, salt_xml, _ = self._request("function_module/login_module/login_page/logintoken_lua.lua")
            if status != 200:
                raise ConnectionError(f"Failed to fetch login salt (HTTP {status})")
                
            salt_m = re.search(r'<ajax_response_xml_root>(\d+)</ajax_response_xml_root>', salt_xml)
            if not salt_m:
                raise RuntimeError(f"Unexpected salt response from router: {salt_xml[:100]}")
            salt = salt_m.group(1)
            
            # 3. Calculate SHA256(password + salt)
            pwd_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
            
            post_data = urllib.parse.urlencode({
                "Username": username,
                "Password": pwd_hash,
                "action": "login",
                "_sessionTOKEN": self.session_token
            })
            
            # 4. Submit login form
            logger.info(f"Authenticating as user '{username}'...")
            status, resp_html, _ = self._request("", method="POST", data=post_data)
            
            if "Welcome, Please login in" in resp_html or "loginWrapper" in resp_html:
                err_m = re.search(r'var login_err_msg = ["\'](.*?)["\']', resp_html)
                err = err_m.group(1) if err_m else "Invalid username or password"
                self.logged_in = False
                logger.error(f"Router login failed: {err}")
                raise PermissionError(f"Router authentication failed: {err}")
                
            self.logged_in = True
            logger.info("Authentication successful. Session established.")
            
            # Update session temporary token
            m_tmp = re.search(r'var _sessionTmpToken = ["\']([^"\']+)["\']', resp_html)
            if m_tmp:
                self.session_token = _clean_token(m_tmp.group(1))
                
            return True

    def ensure_authenticated(self):
        """Re-authenticates automatically if session has expired."""
        with self._lock:
            if not self.logged_in and self.username and self.password:
                logger.info("Session expired, re-authenticating with router...")
                self.login(self.username, self.password)

    def navigate(self, page_name, force=False):
        """
        Navigates to subpage via getpage.lua to initialize router server-side state.
        When force=True, always queries getpage.lua to refresh the _sessionTmpToken.
        """
        with self._lock:
            if not force and self.current_page == page_name:
                return True
                
            url = f"getpage.lua?pid=1002&nextpage={page_name}"
            status, body, _ = self._request(url)
            
            # If session expired, router returns login wrapper
            if "loginWrapper" in body or "Welcome, Please login in" in body:
                logger.warning("Session expired during navigation, re-logging in...")
                self.logged_in = False
                self.ensure_authenticated()
                status, body, _ = self._request(url)

            if status == 200:
                self.current_page = page_name
                # Extract all tokens and take the LAST one (active subpage token)
                tokens = re.findall(r'_sessionTmpToken\s*=\s*[\'"]([^\'"]+)[\'"]', body)
                if tokens:
                    self.session_token = _clean_token(tokens[-1])
                    # Register token with router session via template_csrf check
                    try:
                        csrf_url = f"common_page/template_token_check.lua?sessToken={self.session_token}"
                        self._request(csrf_url)
                    except Exception as e:
                        logger.debug(f"CSRF token check failed: {e}")
                return True
            return False

    def get_xml(self, endpoint):
        """
        Fetches an XML endpoint and parses into ElementTree with auto-retry.
        """
        with self._lock:
            status, body, _ = self._request(endpoint)
            if status != 200 or "loginWrapper" in body:
                if "loginWrapper" in body:
                    logger.warning(f"Session expired fetching {endpoint}, re-authenticating...")
                    self.logged_in = False
                    self.ensure_authenticated()
                    status, body, _ = self._request(endpoint)

            if status != 200:
                logger.error(f"GET {endpoint} returned status {status}")
                return None
                
            try:
                return ET.fromstring(body)
            except ET.ParseError as e:
                logger.error(f"Failed to parse XML from {endpoint}: {e}")
                return None

    def post_data_transfer(self, endpoint, post_data_str, retry=True):
        """
        Executes a ZTE dataPost:
        Calculates SHA256 of payload and adds Check header.
        Automatically recovers from -1452 (Page Expired) by refreshing token and retrying.
        """
        with self._lock:
            # 1. Update or append _sessionTOKEN cleanly (avoid re.sub to eliminate bad escape errors)
            clean_tok = _clean_token(self.session_token)
            parts = [p for p in post_data_str.split('&') if not p.startswith('_sessionTOKEN=')]
            if clean_tok:
                parts.append(f"_sessionTOKEN={clean_tok}")
            post_data_str = "&".join(parts)

            check_hash = hashlib.sha256(post_data_str.encode('utf-8')).hexdigest()
            headers = {
                "Check": check_hash,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            }
            
            status, body, _ = self._request(endpoint, method="POST", data=post_data_str, headers=headers)
            
            # Check for expired page / invalid token (-1452)
            is_expired = ("-1452" in body or "This page has expired" in body or "loginWrapper" in body)
            if is_expired and retry:
                logger.warning("Token expired (-1452). Refreshing subpage session token and retrying...")
                # Re-fetch the proper parent page for the target endpoint
                subpage = "Internet_Dsl_t.lp" if "Internet_Internet" in endpoint else "Internet_AdminInternetStatus_DSL_t.lp"
                self.navigate(subpage, force=True)
                return self.post_data_transfer(endpoint, post_data_str, retry=False)

            if status != 200:
                logger.error(f"POST {endpoint} returned status {status}")
                return False, body
                
            try:
                root = ET.fromstring(body)
                err_str = root.findtext("IF_ERRORSTR", default="SUCC")
                return (err_str == "SUCC"), body
            except Exception:
                return (status == 200), body

    def reboot(self):
        """
        Executes official ZTE router reboot via /common_page/deviceManag_lua.lua.
        """
        with self._lock:
            logger.warning("Initiating router reboot command via deviceManag_lua.lua...")
            self.navigate("ManagDiag_DeviceManag_t.lp", force=True)
            endpoint = "common_page/deviceManag_lua.lua"
            payload = "IF_ACTION=Restart"
            success, body = self.post_data_transfer(endpoint, payload)
            if success:
                logger.info("Reboot command accepted by router.")
                self.logged_in = False
            return success, body

    def logout(self):
        """
        Cleanly log off router to free up the session slot.
        """
        with self._lock:
            if not self.logged_in:
                return
            try:
                data = urllib.parse.urlencode({
                    "IF_LogOff": "1",
                    "sess_token": self.session_token or ""
                })
                self._request("", method="POST", data=data)
                logger.info("Router session closed cleanly.")
            except Exception:
                pass
            finally:
                self.logged_in = False
                self.current_page = None
