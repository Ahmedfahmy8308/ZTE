use std::env;
use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::ptr;
use std::sync::Arc;
use std::thread;

type HMODULE = *mut c_void;
type FARPROC = *mut c_void;
type SOCKET = usize;

const AF_INET: c_int = 2;
const SOCK_STREAM: c_int = 1;
const IPPROTO_TCP: c_int = 6;
const INVALID_SOCKET: SOCKET = !0;
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const TLS1_VERSION: c_long = 0x0301;
const SSL_OP_LEGACY_SERVER_CONNECT: u64 = 0x0000_0004;

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct WSAData {
    _opaque: [u8; 408],
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const c_char) -> HMODULE;
    fn GetProcAddress(h_module: HMODULE, lp_proc_name: *const c_char) -> FARPROC;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(w_version_requested: u16, lp_wsa_data: *mut WSAData) -> c_int;
    fn socket(af: c_int, kind: c_int, protocol: c_int) -> SOCKET;
    fn bind(s: SOCKET, name: *const SockAddrIn, namelen: c_int) -> c_int;
    fn connect(s: SOCKET, name: *const SockAddrIn, namelen: c_int) -> c_int;
    fn closesocket(s: SOCKET) -> c_int;
}

struct OpenSsl {
    _lib: HMODULE,
    tls_client_method: unsafe extern "C" fn() -> *const c_void,
    ssl_ctx_new: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    ssl_ctx_set_cipher_list: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    ssl_ctx_set_security_level: unsafe extern "C" fn(*mut c_void, c_int),
    ssl_ctx_set_options: unsafe extern "C" fn(*mut c_void, u64) -> u64,
    ssl_ctx_ctrl: unsafe extern "C" fn(*mut c_void, c_int, c_long, *mut c_void) -> c_long,
    ssl_new: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    ssl_set_fd: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    ssl_connect: unsafe extern "C" fn(*mut c_void) -> c_int,
    ssl_get_error: unsafe extern "C" fn(*const c_void, c_int) -> c_int,
    ssl_write: unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int,
    ssl_read: unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int,
    ssl_free: unsafe extern "C" fn(*mut c_void),
    ssl_ctx_free: unsafe extern "C" fn(*mut c_void),
}

unsafe impl Send for OpenSsl {}
unsafe impl Sync for OpenSsl {}

unsafe fn load_sym<T>(module: HMODULE, name: &str) -> Result<T, String> {
    let cname = CString::new(name).unwrap();
    let ptr = GetProcAddress(module, cname.as_ptr());
    if ptr.is_null() {
        return Err(format!("Missing OpenSSL symbol: {name}"));
    }
    Ok(std::mem::transmute_copy(&ptr))
}

impl OpenSsl {
    fn load() -> Result<Self, String> {
        let candidates = [
            r"C:\Program Files\Python311\DLLs\libssl-3-x64.dll",
            r"C:\Program Files\Python312\DLLs\libssl-3-x64.dll",
            r"C:\Program Files\Git\mingw64\bin\libssl-3-x64.dll",
            r"libssl-3-x64.dll",
        ];
        unsafe {
            let mut wsa: WSAData = std::mem::zeroed();
            WSAStartup(0x0202, &mut wsa);

            let mut lib: HMODULE = ptr::null_mut();
            for path in &candidates {
                let cpath = CString::new(*path).unwrap();
                lib = LoadLibraryA(cpath.as_ptr());
                if !lib.is_null() {
                    break;
                }
            }
            if lib.is_null() {
                return Err("Could not load libssl-3-x64.dll".into());
            }
            let init_ssl: unsafe extern "C" fn(u64, *const c_void) -> c_int =
                load_sym(lib, "OPENSSL_init_ssl")?;
            init_ssl(0, ptr::null());

            Ok(Self {
                _lib: lib,
                tls_client_method: load_sym(lib, "TLS_client_method")?,
                ssl_ctx_new: load_sym(lib, "SSL_CTX_new")?,
                ssl_ctx_set_cipher_list: load_sym(lib, "SSL_CTX_set_cipher_list")?,
                ssl_ctx_set_security_level: load_sym(lib, "SSL_CTX_set_security_level")?,
                ssl_ctx_set_options: load_sym(lib, "SSL_CTX_set_options")?,
                ssl_ctx_ctrl: load_sym(lib, "SSL_CTX_ctrl")?,
                ssl_new: load_sym(lib, "SSL_new")?,
                ssl_set_fd: load_sym(lib, "SSL_set_fd")?,
                ssl_connect: load_sym(lib, "SSL_connect")?,
                ssl_get_error: load_sym(lib, "SSL_get_error")?,
                ssl_write: load_sym(lib, "SSL_write")?,
                ssl_read: load_sym(lib, "SSL_read")?,
                ssl_free: load_sym(lib, "SSL_free")?,
                ssl_ctx_free: load_sym(lib, "SSL_CTX_free")?,
            })
        }
    }

    fn request(
        &self,
        bind_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        target_port: u16,
        raw_http: &[u8],
    ) -> Result<Vec<u8>, String> {
        unsafe {
            let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if sock == INVALID_SOCKET {
                return Err("socket() failed".into());
            }
            let local_addr = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: u32::from(bind_ip).to_be(),
                sin_zero: [0; 8],
            };
            if bind(sock, &local_addr, std::mem::size_of::<SockAddrIn>() as c_int) != 0 {
                closesocket(sock);
                return Err(format!("bind({bind_ip}) failed"));
            }
            let remote_addr = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: target_port.to_be(),
                sin_addr: u32::from(target_ip).to_be(),
                sin_zero: [0; 8],
            };
            if connect(sock, &remote_addr, std::mem::size_of::<SockAddrIn>() as c_int) != 0 {
                closesocket(sock);
                return Err(format!("connect({target_ip}:{target_port}) failed"));
            }

            let method = (self.tls_client_method)();
            let ctx = (self.ssl_ctx_new)(method);
            if ctx.is_null() {
                closesocket(sock);
                return Err("SSL_CTX_new failed".into());
            }
            let ciphers = CString::new("DEFAULT:@SECLEVEL=0").unwrap();
            (self.ssl_ctx_set_security_level)(ctx, 0);
            (self.ssl_ctx_set_options)(ctx, SSL_OP_LEGACY_SERVER_CONNECT);
            (self.ssl_ctx_set_cipher_list)(ctx, ciphers.as_ptr());
            (self.ssl_ctx_ctrl)(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_VERSION, ptr::null_mut());

            let ssl = (self.ssl_new)(ctx);
            if ssl.is_null() {
                (self.ssl_ctx_free)(ctx);
                closesocket(sock);
                return Err("SSL_new failed".into());
            }
            (self.ssl_set_fd)(ssl, sock as c_int);
            let rc = (self.ssl_connect)(ssl);
            if rc != 1 {
                let err_code = (self.ssl_get_error)(ssl, rc);
                (self.ssl_free)(ssl);
                (self.ssl_ctx_free)(ctx);
                closesocket(sock);
                return Err(format!("SSL_connect failed (rc={rc}, ssl_err={err_code})"));
            }

            let mut written = 0usize;
            while written < raw_http.len() {
                let n = (self.ssl_write)(
                    ssl,
                    raw_http[written..].as_ptr() as *const c_void,
                    (raw_http.len() - written) as c_int,
                );
                if n <= 0 {
                    break;
                }
                written += n as usize;
            }

            let mut resp = Vec::with_capacity(16384);
            let mut buf = [0u8; 16384];
            let mut header_end: Option<usize> = None;
            let mut expected_total: Option<usize> = None;
            loop {
                let n = (self.ssl_read)(ssl, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int);
                if n <= 0 {
                    break;
                }
                resp.extend_from_slice(&buf[..n as usize]);
                if header_end.is_none() {
                    if let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                        let hend = pos + 4;
                        header_end = Some(hend);
                        let hdr_s = String::from_utf8_lossy(&resp[..hend]);
                        for line in hdr_s.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    if let Ok(cl) = v.trim().parse::<usize>() {
                                        expected_total = Some(hend + cl);
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(total) = expected_total {
                    if resp.len() >= total {
                        break;
                    }
                }
            }

            (self.ssl_free)(ssl);
            (self.ssl_ctx_free)(ctx);
            closesocket(sock);
            Ok(resp)
        }
    }
}

// --- Auto-Discovery of Local Interfaces ---

fn list_local_ipv4s() -> Vec<(String, Ipv4Addr)> {
    let Ok(out) = Command::new("ipconfig").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut results = Vec::new();
    let mut current_adapter = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            current_adapter = trimmed.trim_end_matches(':').to_string();
        } else if trimmed.starts_with("IPv4 Address") {
            if let Some((_, rhs)) = trimmed.split_once(':') {
                let ip_str = rhs.trim().trim_end_matches("(Preferred)").trim();
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if !ip.is_loopback() && !ip.is_link_local() {
                        results.push((current_adapter.clone(), ip));
                    }
                }
            }
        }
    }
    results
}

fn decode_html_title(html: &str) -> String {
    let Some(s) = html.find("<title>") else {
        return String::new();
    };
    let Some(e) = html[s + 7..].find("</title>") else {
        return String::new();
    };
    let raw = &html[s + 7..s + 7 + e];
    // Decode numeric HTML entities like &#90;&#88;...
    let mut out = String::new();
    let mut i = 0;
    let bytes = raw.as_bytes();
    while i < bytes.len() {
        if raw[i..].starts_with("&#") {
            if let Some(semi) = raw[i + 2..].find(';') {
                if let Ok(code) = raw[i + 2..i + 2 + semi].parse::<u32>() {
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                        i += 2 + semi + 1;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn detect_h168n_ip(ssl: &OpenSsl, target_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let req = format!("GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n");
    for (adapter, ip) in list_local_ipv4s() {
        if let Ok(raw) = ssl.request(ip, target_ip, 443, req.as_bytes()) {
            let text = String::from_utf8_lossy(&raw);
            let title = decode_html_title(&text);
            if title.contains("H168N") || text.contains("V3.1.0_UEG") || text.contains("wizardcontrol") {
                println!("[Auto-Detect] Found ZXHN H168N on '{adapter}' ({ip}) -> Title: {title}");
                return Some(ip);
            }
        }
    }
    None
}

fn run_detect(ssl: &OpenSsl, target_ip: Ipv4Addr) {
    println!("Scanning local IPv4 adapters for routers at https://{target_ip}:443 ...");
    let req = format!("GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n");
    for (adapter, ip) in list_local_ipv4s() {
        match ssl.request(ip, target_ip, 443, req.as_bytes()) {
            Ok(raw) => {
                let text = String::from_utf8_lossy(&raw);
                let title = decode_html_title(&text);
                println!("  [OK] {adapter:<32} {ip:<15} -> Title: {}", if title.is_empty() { "(unknown)" } else { &title });
            }
            Err(e) => {
                println!("  [--] {adapter:<32} {ip:<15} -> {e}");
            }
        }
    }
}

// --- HTTP Proxy Helpers ---

fn read_http_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 65536 {
            return None;
        }
    }
    let hdr_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut content_len = 0usize;
    for line in hdr_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    while buf.len() < header_end + content_len {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Some(buf)
}

fn rewrite_request(raw: &[u8], target_host: &str, local_host: &str) -> Vec<u8> {
    let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return raw.to_vec();
    };
    let hdr = String::from_utf8_lossy(&raw[..pos]);
    let body = &raw[pos + 4..];

    let mut out = String::new();
    for (idx, line) in hdr.split("\r\n").enumerate() {
        if idx == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if kl == "host" {
                out.push_str(&format!("Host: {target_host}\r\n"));
            } else if kl == "connection" || kl == "accept-encoding" {
                continue;
            } else if kl == "origin" || kl == "referer" {
                let replaced = v.trim().replace(&format!("http://{local_host}"), &format!("https://{target_host}"));
                out.push_str(&format!("{k}: {replaced}\r\n"));
            } else {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
    }
    out.push_str("Connection: close\r\nAccept-Encoding: identity\r\n\r\n");
    let mut res = out.into_bytes();
    res.extend_from_slice(body);
    res
}

fn rewrite_response(raw: &[u8], target_host: &str, local_host: &str) -> Vec<u8> {
    let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return raw.to_vec();
    };
    let hdr = String::from_utf8_lossy(&raw[..pos]);
    let body = &raw[pos + 4..];

    let mut out = String::new();
    for (idx, line) in hdr.split("\r\n").enumerate() {
        if idx == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if kl == "location" {
                let replaced = v
                    .trim()
                    .replace(&format!("https://{target_host}"), &format!("http://{local_host}"))
                    .replace(&format!("http://{target_host}"), &format!("http://{local_host}"));
                out.push_str(&format!("Location: {replaced}\r\n"));
            } else if kl == "set-cookie" {
                let cleaned = v.replace("; Secure", "").replace("; secure", "");
                out.push_str(&format!("Set-Cookie:{cleaned}\r\n"));
            } else if kl == "content-security-policy" || kl == "strict-transport-security" {
                continue;
            } else {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
    }
    out.push_str("\r\n");
    let mut res = out.into_bytes();
    res.extend_from_slice(body);
    res
}

fn run_proxy(ssl: Arc<OpenSsl>, bind_ip: Ipv4Addr, target_ip: Ipv4Addr, port: u16) {
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(listen_addr).expect("Failed to bind local proxy port");
    let local_host = format!("127.0.0.1:{port}");
    let target_host = target_ip.to_string();
    println!("========================================================");
    println!("  ZTE ZXHN H168N V3.1 - Rust TLS 1.0 Reverse Proxy");
    println!("  Local URL   : http://{local_host}");
    println!("  Source NIC  : {bind_ip} -> https://{target_host}:443");
    println!("========================================================");

    for stream in listener.incoming().flatten() {
        let ssl = Arc::clone(&ssl);
        let local_host = local_host.clone();
        let target_host = target_host.clone();
        thread::spawn(move || {
            let mut client = stream;
            let Some(req_bytes) = read_http_request(&mut client) else {
                return;
            };
            let fwd = rewrite_request(&req_bytes, &target_host, &local_host);
            match ssl.request(bind_ip, target_ip, 443, &fwd) {
                Ok(resp) => {
                    let fixed = rewrite_response(&resp, &target_host, &local_host);
                    let _ = client.write_all(&fixed);
                }
                Err(e) => {
                    let msg = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nProxy Error: {e}"
                    );
                    let _ = client.write_all(msg.as_bytes());
                }
            }
        });
    }
}

fn extract_xml_para(xml: &str, name: &str) -> Option<String> {
    let needle = format!("<ParaName>{name}</ParaName><ParaValue>");
    let start = xml.find(&needle)? + needle.len();
    let end = xml[start..].find("</ParaValue>")?;
    Some(xml[start..start + end].to_string())
}

fn run_info(ssl: &OpenSsl, bind_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let body = "IF_ACTION=wlan_get";
    let req = format!(
        "POST /wizardcontrol.html HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    match ssl.request(bind_ip, target_ip, 443, req.as_bytes()) {
        Ok(raw) => {
            let text = String::from_utf8_lossy(&raw);
            println!("=== ZXHN H168N V3.1 Status ({bind_ip} -> {target_ip}) ===");
            println!("  Wi-Fi SSID     : {}", extract_xml_para(&text, "ESSID").unwrap_or_else(|| "N/A".into()));
            println!("  Wi-Fi Password : {}", extract_xml_para(&text, "KeyPassphrase").unwrap_or_else(|| "N/A".into()));
            println!("  Radio Status   : {}", extract_xml_para(&text, "RadioStatus").unwrap_or_else(|| "N/A".into()));
            println!(
                "  Auth / Enc     : {} / {}",
                extract_xml_para(&text, "BeaconType").unwrap_or_else(|| "N/A".into()),
                extract_xml_para(&text, "11iEncryptType").unwrap_or_else(|| "N/A".into())
            );
        }
        Err(e) => eprintln!("Error querying router: {e}"),
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn run_set_wifi(ssl: &OpenSsl, bind_ip: Ipv4Addr, target_ip: Ipv4Addr, ssid: &str, pass: &str) {
    let body = format!(
        "IF_ACTION=wlan_set&_InstID=DEV.WIFI.RD1&RadioStatus=1&_InstID_AP=DEV.WIFI.AP1&ESSID={}&BeaconType=11i&11iAuthMode=PSKAuthentication&11iEncryptType=AESEncryption&_InstID_PSK=DEV.WIFI.AP1.PSK1&KeyPassphrase={}",
        url_encode(ssid),
        url_encode(pass)
    );
    let req = format!(
        "POST /wizardcontrol.html HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    match ssl.request(bind_ip, target_ip, 443, req.as_bytes()) {
        Ok(raw) => {
            let text = String::from_utf8_lossy(&raw);
            if text.contains("<IF_ERRORID>0</IF_ERRORID>") {
                println!("[OK] Wi-Fi updated: SSID='{ssid}'");
            } else {
                eprintln!("[WARN] Router response:\n{text}");
            }
        }
        Err(e) => eprintln!("Error updating Wi-Fi: {e}"),
    }
}

fn print_usage() {
    println!("ZTE ZXHN H168N Rust Toolkit (h168n-cli)");
    println!("Usage:");
    println!("  h168n-cli detect [--target 192.168.1.1]");
    println!("  h168n-cli info   [--bind-ip <IP>] [--target 192.168.1.1]");
    println!("  h168n-cli proxy  [--bind-ip <IP>] [--target 192.168.1.1] [--port 8081]");
    println!("  h168n-cli set-wifi --ssid <NAME> --pass <PASS> [--bind-ip <IP>]");
    println!("  h168n-cli zcu-decode <input.bin> <output.xml> [--key <KEY>] [--iv <IV>] [--serial <SN>] [--mac <MAC>]");
    println!("  h168n-cli zcu-encode <input.xml> <output.bin> [--type 2|3|4] [--sig \"ZXHN H168N V3.1\"] [--key <KEY>] [--iv <IV>]");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(cmd) = args.get(1).map(|s| s.as_str()) else {
        print_usage();
        return;
    };

    if cmd == "zcu-decode" {
        let Some(in_path) = args.get(2) else { print_usage(); return; };
        let Some(out_path) = args.get(3) else { print_usage(); return; };
        let mut key: Option<String> = None;
        let mut iv: Option<String> = None;
        let mut serial: Option<String> = None;
        let mut mac: Option<String> = None;
        let mut i = 4;
        while i < args.len() {
            match args[i].as_str() {
                "--key" if i + 1 < args.len() => { key = Some(args[i + 1].clone()); i += 2; }
                "--iv" if i + 1 < args.len() => { iv = Some(args[i + 1].clone()); i += 2; }
                "--serial" if i + 1 < args.len() => { serial = Some(args[i + 1].clone()); i += 2; }
                "--mac" if i + 1 < args.len() => { mac = Some(args[i + 1].clone()); i += 2; }
                _ => i += 1,
            }
        }
        let data = fs::read(in_path).expect("Failed to read input config.bin");
        let res = if key.is_some() {
            zcu_rs::decode_config(&data, key.as_deref(), iv.as_deref())
        } else {
            zcu_rs::auto_decode_config(&data, &zcu_rs::AutoKeygenParams {
                serial,
                mac,
                ..Default::default()
            })
        };
        match res {
            Ok(dec) => {
                fs::write(out_path, &dec.xml).expect("Failed to write output XML");
                println!("[OK] Decoded {} -> {} (sig='{}', type={}, key='{}', {} bytes)", in_path, out_path, dec.signature, dec.payload_type, dec.used_key, dec.xml.len());
            }
            Err(e) => {
                eprintln!("[ERROR] Decode failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if cmd == "zcu-encode" {
        let Some(in_path) = args.get(2) else { print_usage(); return; };
        let Some(out_path) = args.get(3) else { print_usage(); return; };
        let mut sig = "ZXHN H168N V3.1".to_string();
        let mut key: Option<String> = None;
        let mut iv: Option<String> = None;
        let mut payload_type: u32 = 2;
        let mut i = 4;
        while i < args.len() {
            match args[i].as_str() {
                "--type" if i + 1 < args.len() => { payload_type = args[i + 1].parse().unwrap_or(2); i += 2; }
                "--sig" if i + 1 < args.len() => { sig = args[i + 1].clone(); i += 2; }
                "--key" if i + 1 < args.len() => { key = Some(args[i + 1].clone()); i += 2; }
                "--iv" if i + 1 < args.len() => { iv = Some(args[i + 1].clone()); i += 2; }
                _ => i += 1,
            }
        }
        let k = key
            .or_else(|| zcu_rs::find_known_key(&sig).map(str::to_string))
            .unwrap_or_else(|| format!("{sig}Key02721401"));
        let xml = fs::read(in_path).expect("Failed to read input XML");
        match zcu_rs::encode_config(&xml, payload_type, &sig, &k, iv.as_deref(), true) {
            Ok(bin) => {
                fs::write(out_path, &bin).expect("Failed to write output config.bin");
                println!("[OK] Encoded {} -> {} (sig='{}', type={}, {} bytes)", in_path, out_path, sig, payload_type, bin.len());
            }
            Err(e) => {
                eprintln!("[ERROR] Encode failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let mut bind_ip: Option<Ipv4Addr> = None;
    let mut target_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
    let mut port: u16 = 8081;
    let mut ssid = String::new();
    let mut pass = String::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--bind-ip" if i + 1 < args.len() => { bind_ip = Some(args[i + 1].parse().expect("Invalid --bind-ip")); i += 2; }
            "--target" if i + 1 < args.len() => { target_ip = args[i + 1].parse().expect("Invalid --target"); i += 2; }
            "--port" if i + 1 < args.len() => { port = args[i + 1].parse().expect("Invalid --port"); i += 2; }
            "--ssid" if i + 1 < args.len() => { ssid = args[i + 1].clone(); i += 2; }
            "--pass" if i + 1 < args.len() => { pass = args[i + 1].clone(); i += 2; }
            _ => i += 1,
        }
    }

    let ssl = Arc::new(OpenSsl::load().expect("Failed to initialize OpenSSL"));
    if cmd == "detect" {
        run_detect(&ssl, target_ip);
        return;
    }

    let resolved_bind = bind_ip.unwrap_or_else(|| {
        detect_h168n_ip(&ssl, target_ip).expect("Could not auto-detect ZXHN H168N interface; pass --bind-ip")
    });

    match cmd {
        "proxy" => run_proxy(ssl, resolved_bind, target_ip, port),
        "info" => run_info(&ssl, resolved_bind, target_ip),
        "set-wifi" => {
            if ssid.is_empty() || pass.is_empty() {
                eprintln!("--ssid and --pass are required");
                return;
            }
            run_set_wifi(&ssl, resolved_bind, target_ip, &ssid, &pass);
        }
        _ => print_usage(),
    }
}
