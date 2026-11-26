use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

fn inspect_h188a_bin(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] Cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    if data.len() < 256 {
        eprintln!("[ERROR] File too small to be a ZTE firmware image");
        std::process::exit(1);
    }
    let magic = &data[0..16];
    let expected_magic: [u8; 16] = [
        0x99, 0x99, 0x99, 0x99, 0x44, 0x44, 0x44, 0x44,
        0x55, 0x55, 0x55, 0x55, 0xAA, 0xAA, 0xAA, 0xAA,
    ];
    let magic_ok = magic == expected_magic;
    let ver = String::from_utf8_lossy(&data[0x4c..0x6c])
        .split('\0')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let model = String::from_utf8_lossy(&data[0xa8..0xc8])
        .split('\0')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let sqsh_off = data.windows(4).position(|w| w == b"hsqs");
    let lzma_off = data[..0x200.min(data.len())].windows(4).position(|w| w == b"\x5d\x00\x00\x80");

    println!("=== ZTE ZXHN H188A Firmware Inspector (Rust) ===");
    println!("  File       : {path} ({} bytes)", data.len());
    println!("  ZTE Magic  : {}", if magic_ok { "VALID" } else { "INVALID" });
    println!("  Version    : {ver}");
    println!("  Model Tag  : {model}");
    println!("  LZMA Kernel: {}", lzma_off.map_or("Not found".into(), |o| format!("0x{o:x}")));
    println!("  SquashFS   : {}", sqsh_off.map_or("Not found".into(), |o| format!("0x{o:x}")));
}

fn check_reachability(ip: &str) {
    let addr: SocketAddr = format!("{ip}:443").parse().expect("Invalid IP");
    match TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        Ok(_) => println!("[OK] H188A reachable at https://{ip}:443"),
        Err(e) => println!("[--] H188A not reachable at https://{ip}:443 ({e})"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "fw-inspect" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("../../Firmware/H188a/H188a.bin");
            inspect_h188a_bin(path);
        }
        "ping" => {
            let ip: Ipv4Addr = args.get(2).and_then(|s| s.parse().ok()).unwrap_or_else(|| "192.168.1.1".parse().unwrap());
            check_reachability(&ip.to_string());
        }
        "zcu-decode" => {
            let (Some(inp), Some(outp)) = (args.get(2), args.get(3)) else {
                eprintln!("Usage: h188a-cli zcu-decode <in.bin> <out.xml>");
                return;
            };
            let data = fs::read(inp).expect("Failed to read input");
            match zcu_rs::auto_decode_config(&data, &zcu_rs::AutoKeygenParams {
                signature: Some("H188A".into()),
                ..Default::default()
            }) {
                Ok(dec) => {
                    fs::write(outp, &dec.xml).expect("Failed to write output");
                    println!("[OK] Decoded H188A config -> {outp} (type={}, {} bytes)", dec.payload_type, dec.xml.len());
                }
                Err(e) => {
                    eprintln!("[ERROR] {e}");
                    std::process::exit(1);
                }
            }
        }
        "zcu-encode" => {
            let (Some(inp), Some(outp)) = (args.get(2), args.get(3)) else {
                eprintln!("Usage: h188a-cli zcu-encode <in.xml> <out.bin>");
                return;
            };
            let xml = fs::read(inp).expect("Failed to read XML");
            match zcu_rs::encode_config(&xml, 4, "H188A", "H188AKey02721401", Some("H188AIv02721401"), true) {
                Ok(bin) => {
                    fs::write(outp, &bin).expect("Failed to write config.bin");
                    println!("[OK] Encoded H188A Type-4 config -> {outp} ({} bytes)", bin.len());
                }
                Err(e) => {
                    eprintln!("[ERROR] {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("ZTE ZXHN H188A Rust CLI (h188a-cli)");
            println!("  h188a-cli fw-inspect [path/to/H188a.bin]");
            println!("  h188a-cli ping [192.168.1.1]");
            println!("  h188a-cli zcu-decode <in.bin> <out.xml>");
            println!("  h188a-cli zcu-encode <in.xml> <out.bin>");
        }
    }
}
