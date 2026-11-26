//! Native Rust ZTE `config.bin` codec (`zcu-rs`).
//! Supports ZTE `config.bin` container parsing, Type-0 (ZLIB), Type-2 (AES-128-ECB),
//! Type-3/4 (AES-256-CBC + SHA-256) encryption/decryption, and automatic key derivation
//! from router signatures, serial numbers, and MAC addresses.

use std::ffi::{c_char, c_int, c_uchar, c_void, CString};
use std::ptr;

pub const PAYLOAD_MAGIC: u32 = 0x01020304;
pub const SIGNATURE_MAGIC: u32 = 0x04030201;
pub const ZTE_MAGIC: [u32; 4] = [0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA];

/// Known Type-2 static keys mapped to signature prefixes (lowercase).
pub const KNOWN_KEYS: &[(&str, &[&str])] = &[
    ("MIK@0STzKpB%qJZe", &["zxhn h118n e"]),
    ("MIK@0STzKpB%qJZf", &["zxhn h118n v"]),
    ("402c38de39bed665", &["zxhn h267a"]),
    ("Q#Zxn*x3kVLc", &["zxhn h168n v2"]),
    ("Wj", &["zxhn h298n"]),
    ("m8@96&ZG3Nm7N&Iz", &["zxhn h298a"]),
    ("GrWM2Hz&LTvz&f^5", &["zxhn h108n"]),
    ("GrWM3Hz&LTvz&f^9", &["zxhn h168n v3", "zxhn h168n h"]),
    ("Renjx%2$CjM", &["zxhn h208n", "zxv10 h201l"]),
    ("tHG@Ti&GVh@ql3XN", &["zxhn h267n"]),
];

pub const KNOWN_SIGNATURES: &[&str] = &[
    "H1600",
    "H188A",
    "H196Q",
    "H268Q",
    "H288A",
    "H298Q",
    "ZTEH1600",
];

pub const KNOWN_KEYPAIR_SUFFIXES: &[(&str, &str)] = &[
    ("", ""),
    ("key", "IV"),
    ("Key02660004", "Iv02660004"),
    ("Key02670001", "Iv02670001"),
    ("Key02710001", "Iv02710001"),
    ("Key02710010", "Iv02710010"),
    ("Key02721401", "Iv02721401"),
    ("8cc72b05705d5c46f412af8cbed55aa", "667b02a85c61c786def4521b060265e"),
];

pub const KNOWN_KEYPAIR_PREFIXES: &[(&str, &str)] = &[
    ("", ""),
    ("8cc72b05705d5c46", "667b02a85c61c786"),
    ("8dc79b15726d5c46", "678b02a85c63c786"),
];

pub const KNOWN_KEYPAIRS: &[(&str, &str)] = &[
    ("H267AV1_CZkey", "H267AV1_CZIV"),
    ("8cc72b05705d5c46f412af8cbed55aad", "667b02a85c61c786def4521b060265e8"),
    ("8dc79b15726d5c46d412af8cbed65aad", "678b02a85c63c786def4523b061265e8"),
    ("SR7410Key80748010", "SR7410Iv80748010"),
    ("SR7110Key80718010", "SR7110Iv80718010"),
];

pub fn find_known_key(signature: &str) -> Option<&'static str> {
    let lower = signature.to_ascii_lowercase();
    for (key, prefixes) in KNOWN_KEYS {
        for prefix in *prefixes {
            if lower.starts_with(prefix) {
                return Some(key);
            }
        }
    }
    None
}

// --- Dynamic OpenSSL libcrypto FFI (zero external crates) ---

type HMODULE = *mut c_void;
type FARPROC = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const c_char) -> HMODULE;
    fn GetProcAddress(h_module: HMODULE, lp_proc_name: *const c_char) -> FARPROC;
}

struct LibCrypto {
    _lib: HMODULE,
    sha256: unsafe extern "C" fn(*const c_uchar, usize, *mut c_uchar) -> *mut c_uchar,
    evp_aes_128_ecb: unsafe extern "C" fn() -> *const c_void,
    evp_aes_256_cbc: unsafe extern "C" fn() -> *const c_void,
    evp_cipher_ctx_new: unsafe extern "C" fn() -> *mut c_void,
    evp_cipher_ctx_free: unsafe extern "C" fn(*mut c_void),
    evp_cipher_ctx_set_padding: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    evp_encrypt_init_ex:
        unsafe extern "C" fn(*mut c_void, *const c_void, *mut c_void, *const c_uchar, *const c_uchar) -> c_int,
    evp_encrypt_update:
        unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut c_int, *const c_uchar, c_int) -> c_int,
    evp_encrypt_final_ex: unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut c_int) -> c_int,
    evp_decrypt_init_ex:
        unsafe extern "C" fn(*mut c_void, *const c_void, *mut c_void, *const c_uchar, *const c_uchar) -> c_int,
    evp_decrypt_update:
        unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut c_int, *const c_uchar, c_int) -> c_int,
    evp_decrypt_final_ex: unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut c_int) -> c_int,
}

unsafe fn sym<T>(m: HMODULE, name: &str) -> Result<T, String> {
    let cname = CString::new(name).unwrap();
    let p = GetProcAddress(m, cname.as_ptr());
    if p.is_null() {
        return Err(format!("Missing libcrypto symbol: {name}"));
    }
    Ok(std::mem::transmute_copy(&p))
}

impl LibCrypto {
    fn load() -> Result<Self, String> {
        let candidates = [
            r"C:\Program Files\Python311\DLLs\libcrypto-3-x64.dll",
            r"C:\Program Files\Python312\DLLs\libcrypto-3-x64.dll",
            r"C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll",
            r"libcrypto-3-x64.dll",
        ];
        unsafe {
            let mut lib: HMODULE = ptr::null_mut();
            for p in &candidates {
                let cp = CString::new(*p).unwrap();
                lib = LoadLibraryA(cp.as_ptr());
                if !lib.is_null() {
                    break;
                }
            }
            if lib.is_null() {
                return Err("Could not load libcrypto-3-x64.dll".into());
            }
            Ok(Self {
                _lib: lib,
                sha256: sym(lib, "SHA256")?,
                evp_aes_128_ecb: sym(lib, "EVP_aes_128_ecb")?,
                evp_aes_256_cbc: sym(lib, "EVP_aes_256_cbc")?,
                evp_cipher_ctx_new: sym(lib, "EVP_CIPHER_CTX_new")?,
                evp_cipher_ctx_free: sym(lib, "EVP_CIPHER_CTX_free")?,
                evp_cipher_ctx_set_padding: sym(lib, "EVP_CIPHER_CTX_set_padding")?,
                evp_encrypt_init_ex: sym(lib, "EVP_EncryptInit_ex")?,
                evp_encrypt_update: sym(lib, "EVP_EncryptUpdate")?,
                evp_encrypt_final_ex: sym(lib, "EVP_EncryptFinal_ex")?,
                evp_decrypt_init_ex: sym(lib, "EVP_DecryptInit_ex")?,
                evp_decrypt_update: sym(lib, "EVP_DecryptUpdate")?,
                evp_decrypt_final_ex: sym(lib, "EVP_DecryptFinal_ex")?,
            })
        }
    }

    fn sha256_digest(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            (self.sha256)(data.as_ptr(), data.len(), out.as_mut_ptr());
        }
        out
    }

    fn aes_crypt(
        &self,
        cipher: *const c_void,
        key: &[u8],
        iv: Option<&[u8]>,
        input: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>, String> {
        unsafe {
            let ctx = (self.evp_cipher_ctx_new)();
            if ctx.is_null() {
                return Err("EVP_CIPHER_CTX_new failed".into());
            }
            let iv_ptr = iv.map_or(ptr::null(), |v| v.as_ptr());
            let ok = if encrypt {
                (self.evp_encrypt_init_ex)(ctx, cipher, ptr::null_mut(), key.as_ptr(), iv_ptr)
            } else {
                (self.evp_decrypt_init_ex)(ctx, cipher, ptr::null_mut(), key.as_ptr(), iv_ptr)
            };
            if ok != 1 {
                (self.evp_cipher_ctx_free)(ctx);
                return Err("EVP_CipherInit_ex failed".into());
            }
            (self.evp_cipher_ctx_set_padding)(ctx, 0);

            let mut out = vec![0u8; input.len() + 32];
            let mut out_len: c_int = 0;
            let mut fin_len: c_int = 0;
            let ok2 = if encrypt {
                (self.evp_encrypt_update)(ctx, out.as_mut_ptr(), &mut out_len, input.as_ptr(), input.len() as c_int)
            } else {
                (self.evp_decrypt_update)(ctx, out.as_mut_ptr(), &mut out_len, input.as_ptr(), input.len() as c_int)
            };
            let ok3 = if encrypt {
                (self.evp_encrypt_final_ex)(ctx, out[out_len as usize..].as_mut_ptr(), &mut fin_len)
            } else {
                (self.evp_decrypt_final_ex)(ctx, out[out_len as usize..].as_mut_ptr(), &mut fin_len)
            };
            (self.evp_cipher_ctx_free)(ctx);
            if ok2 != 1 || ok3 != 1 {
                return Err("AES operation failed".into());
            }
            out.truncate((out_len + fin_len) as usize);
            Ok(out)
        }
    }
}

// --- CRC32 & Adler32 ---

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

// --- Pure Rust ZLIB Stored Encoder & RFC-1951 Inflate Decoder ---

pub fn zlib_compress_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    out.push(0x78);
    out.push(0x01);
    let mut pos = 0;
    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        while pos < data.len() {
            let end = (pos + 65535).min(data.len());
            let chunk = &data[pos..end];
            let bfinal = if end == data.len() { 0x01 } else { 0x00 };
            let len = chunk.len() as u16;
            let nlen = !len;
            out.push(bfinal);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(chunk);
            pos = end;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_buf: u32,
    bit_cnt: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, byte_pos: 0, bit_buf: 0, bit_cnt: 0 }
    }
    fn ensure(&mut self, n: u8) -> Result<(), String> {
        while self.bit_cnt < n {
            if self.byte_pos >= self.data.len() {
                return Err("Unexpected EOF in deflate stream".into());
            }
            self.bit_buf |= (self.data[self.byte_pos] as u32) << self.bit_cnt;
            self.byte_pos += 1;
            self.bit_cnt += 8;
        }
        Ok(())
    }
    fn read_bits(&mut self, n: u8) -> Result<u32, String> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure(n)?;
        let val = self.bit_buf & ((1u32 << n) - 1);
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        Ok(val)
    }
    fn align_byte(&mut self) {
        let drop = self.bit_cnt & 7;
        self.bit_buf >>= drop;
        self.bit_cnt -= drop;
    }
    fn read_u16_le(&mut self) -> Result<u16, String> {
        self.align_byte();
        let lo = self.read_bits(8)? as u16;
        let hi = self.read_bits(8)? as u16;
        Ok(lo | (hi << 8))
    }
}

struct HuffTree {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l as usize >= 16 {
                return Err("Invalid Huffman code length".into());
            }
            if l > 0 {
                counts[l as usize] += 1;
            }
        }
        let mut offsets = [0u16; 16];
        let mut total = 0u16;
        for bits in 1..16 {
            offsets[bits] = total;
            total += counts[bits];
        }
        let mut symbols = vec![0u16; total as usize];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let idx = offsets[len as usize] as usize;
                offsets[len as usize] += 1;
                symbols[idx] = sym as u16;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader) -> Result<u16, String> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= br.read_bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("Invalid Huffman code in deflate stream".into())
    }
}

pub fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 6 {
        return Err("ZLIB data too short".into());
    }
    let cmf = input[0];
    let flg = input[1];
    if (cmf & 0x0F) != 8 || (((cmf as u16) * 256 + flg as u16) % 31) != 0 {
        return Err("Invalid ZLIB header".into());
    }
    let mut start = 2;
    if (flg & 0x20) != 0 {
        start += 4;
    }
    let mut br = BitReader::new(&input[start..input.len() - 4]);
    let mut out = Vec::new();

    const LEN_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LEN_EXT: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXT: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    const CL_ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        if btype == 0 {
            let len = br.read_u16_le()? as usize;
            let nlen = br.read_u16_le()?;
            if len as u16 != !nlen {
                return Err("Corrupt stored deflate block".into());
            }
            for _ in 0..len {
                out.push(br.read_bits(8)? as u8);
            }
        } else if btype == 1 || btype == 2 {
            let (lit_tree, dist_tree) = if btype == 1 {
                let mut lit_lens = vec![0u8; 288];
                for l in &mut lit_lens[0..=143] { *l = 8; }
                for l in &mut lit_lens[144..=255] { *l = 9; }
                for l in &mut lit_lens[256..=279] { *l = 7; }
                for l in &mut lit_lens[280..=287] { *l = 8; }
                let dist_lens = vec![5u8; 32];
                (HuffTree::from_lengths(&lit_lens)?, HuffTree::from_lengths(&dist_lens)?)
            } else {
                let hlit = br.read_bits(5)? as usize + 257;
                let hdist = br.read_bits(5)? as usize + 1;
                let hclen = br.read_bits(4)? as usize + 4;
                let mut cl_lens = [0u8; 19];
                for i in 0..hclen {
                    cl_lens[CL_ORDER[i]] = br.read_bits(3)? as u8;
                }
                let cl_tree = HuffTree::from_lengths(&cl_lens)?;
                let mut lens = Vec::with_capacity(hlit + hdist);
                while lens.len() < hlit + hdist {
                    let sym = cl_tree.decode(&mut br)?;
                    match sym {
                        0..=15 => lens.push(sym as u8),
                        16 => {
                            let rep = br.read_bits(2)? as usize + 3;
                            let prev = *lens.last().ok_or("Bad repeat in deflate")?;
                            lens.resize(lens.len() + rep, prev);
                        }
                        17 => {
                            let rep = br.read_bits(3)? as usize + 3;
                            lens.resize(lens.len() + rep, 0);
                        }
                        18 => {
                            let rep = br.read_bits(7)? as usize + 11;
                            lens.resize(lens.len() + rep, 0);
                        }
                        _ => return Err("Invalid code-length symbol".into()),
                    }
                }
                (
                    HuffTree::from_lengths(&lens[..hlit])?,
                    HuffTree::from_lengths(&lens[hlit..])?,
                )
            };

            loop {
                let sym = lit_tree.decode(&mut br)?;
                if sym < 256 {
                    out.push(sym as u8);
                } else if sym == 256 {
                    break;
                } else {
                    let idx = (sym - 257) as usize;
                    if idx >= LEN_BASE.len() {
                        return Err("Invalid length symbol".into());
                    }
                    let length = LEN_BASE[idx] as usize + br.read_bits(LEN_EXT[idx])? as usize;
                    let d_sym = dist_tree.decode(&mut br)? as usize;
                    if d_sym >= DIST_BASE.len() {
                        return Err("Invalid distance symbol".into());
                    }
                    let dist = DIST_BASE[d_sym] as usize + br.read_bits(DIST_EXT[d_sym])? as usize;
                    if dist == 0 || dist > out.len() {
                        return Err("Invalid back-reference distance".into());
                    }
                    for _ in 0..length {
                        let b = out[out.len() - dist];
                        out.push(b);
                    }
                }
            }
        } else {
            return Err("Reserved deflate block type 3".into());
        }
        if bfinal != 0 {
            break;
        }
    }
    Ok(out)
}

// --- ZTE config.bin High-Level Codec ---

fn read_be_u32(buf: &[u8], off: usize) -> Result<u32, String> {
    let slice: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or("Unexpected EOF reading u32")?
        .try_into()
        .unwrap();
    Ok(u32::from_be_bytes(slice))
}

#[derive(Default)]
pub struct AutoKeygenParams {
    pub signature: Option<String>,
    pub serial: Option<String>,
    pub mac: Option<String>,
    pub long_pass: Option<String>,
}

pub struct DecodedConfig {
    pub signature: String,
    pub payload_type: u32,
    pub used_key: String,
    pub used_iv: String,
    pub xml: Vec<u8>,
}

/// Decodes a ZTE `config.bin` file (Type 0 / 2 / 3 / 4) into raw XML bytes.
pub fn decode_config(
    data: &[u8],
    key: Option<&str>,
    iv: Option<&str>,
) -> Result<DecodedConfig, String> {
    let mut pos = 0usize;
    if data.len() >= 128
        && read_be_u32(data, 0)? == ZTE_MAGIC[0]
        && read_be_u32(data, 4)? == ZTE_MAGIC[1]
        && read_be_u32(data, 8)? == ZTE_MAGIC[2]
        && read_be_u32(data, 12)? == ZTE_MAGIC[3]
    {
        pos = 128;
    }

    let mut signature = String::new();
    if pos + 12 <= data.len() && read_be_u32(data, pos)? == SIGNATURE_MAGIC {
        let sig_len = read_be_u32(data, pos + 8)? as usize;
        pos += 12;
        let sig_bytes = data.get(pos..pos + sig_len).ok_or("Truncated signature")?;
        signature = String::from_utf8_lossy(sig_bytes).trim_end_matches('\0').to_string();
        pos += sig_len;
    }

    let payload = &data[pos..];
    if payload.len() < 60 || read_be_u32(payload, 0)? != PAYLOAD_MAGIC {
        return Err("Invalid ZTE payload header".into());
    }
    let payload_type = read_be_u32(payload, 4)?;
    let body = &payload[60..];
    let crypto = LibCrypto::load()?;

    match payload_type {
        0 => {
            let mut bpos = 0usize;
            let mut xml = Vec::new();
            loop {
                let dec_len = read_be_u32(body, bpos)? as usize;
                let comp_len = read_be_u32(body, bpos + 4)? as usize;
                let more = read_be_u32(body, bpos + 8)?;
                bpos += 12;
                let chunk = body.get(bpos..bpos + comp_len).ok_or("Truncated zlib chunk")?;
                bpos += comp_len;
                let dec = zlib_decompress(chunk)?;
                if dec.len() != dec_len {
                    return Err(format!("Decompressed length mismatch: {} vs {dec_len}", dec.len()));
                }
                xml.extend_from_slice(&dec);
                if more == 0 {
                    break;
                }
            }
            Ok(DecodedConfig {
                signature,
                payload_type,
                used_key: String::new(),
                used_iv: String::new(),
                xml,
            })
        }
        2 => {
            let k_str = key
                .or_else(|| find_known_key(&signature))
                .ok_or("Type-2 key required (pass --key or signature)")?;
            let mut k_bytes = [0u8; 16];
            let raw_k = k_str.as_bytes();
            let copy_n = raw_k.len().min(16);
            k_bytes[..copy_n].copy_from_slice(&raw_k[..copy_n]);

            let mut bpos = 0usize;
            let mut enc_buf = Vec::new();
            let mut total_dec = 0usize;
            loop {
                let chunk_sz = read_be_u32(body, bpos)? as usize;
                let dec_sz = read_be_u32(body, bpos + 4)? as usize;
                let more = read_be_u32(body, bpos + 8)?;
                bpos += 12;
                enc_buf.extend_from_slice(body.get(bpos..bpos + chunk_sz).ok_or("Truncated AES block")?);
                bpos += chunk_sz;
                total_dec += dec_sz;
                if more == 0 {
                    break;
                }
            }
            let mut dec = crypto.aes_crypt(unsafe { (crypto.evp_aes_128_ecb)() }, &k_bytes, None, &enc_buf, false)?;
            dec.truncate(total_dec);
            let inner = decode_config(&dec, None, None)?;
            Ok(DecodedConfig {
                signature,
                payload_type,
                used_key: k_str.to_string(),
                used_iv: String::new(),
                xml: inner.xml,
            })
        }
        3 | 4 => {
            let k_str = key.ok_or("Type-3/4 key required (pass --key)")?;
            let iv_str = iv.unwrap_or(k_str);
            let k_hash = crypto.sha256_digest(k_str.as_bytes());
            let iv_hash = crypto.sha256_digest(iv_str.as_bytes());

            let mut bpos = 0usize;
            let mut enc_buf = Vec::new();
            let mut total_dec = 0usize;
            loop {
                let dec_sz = read_be_u32(body, bpos)? as usize;
                let chunk_sz = read_be_u32(body, bpos + 4)? as usize;
                let more = read_be_u32(body, bpos + 8)?;
                bpos += 12;
                enc_buf.extend_from_slice(body.get(bpos..bpos + chunk_sz).ok_or("Truncated CBC block")?);
                bpos += chunk_sz;
                total_dec += dec_sz;
                if more == 0 {
                    break;
                }
            }
            let mut dec = crypto.aes_crypt(
                unsafe { (crypto.evp_aes_256_cbc)() },
                &k_hash,
                Some(&iv_hash[..16]),
                &enc_buf,
                false,
            )?;
            dec.truncate(total_dec);
            let inner = decode_config(&dec, None, None)?;
            Ok(DecodedConfig {
                signature,
                payload_type,
                used_key: k_str.to_string(),
                used_iv: iv_str.to_string(),
                xml: inner.xml,
            })
        }
        other => Err(format!("Unsupported ZTE payload type: {other}")),
    }
}

/// Automatically tries known key derivation strategies (signature, serial, MAC, static keys).
pub fn auto_decode_config(data: &[u8], params: &AutoKeygenParams) -> Result<DecodedConfig, String> {
    if let Ok(res) = decode_config(data, None, None) {
        return Ok(res);
    }

    let mut candidates: Vec<(String, Option<String>)> = Vec::new();

    // 1. Static known keys (Type 2)
    for (k, _) in KNOWN_KEYS {
        candidates.push(((*k).to_string(), None));
    }

    // 2. Signature-based keypairs (Type 3/4)
    let mut sigs: Vec<String> = Vec::new();
    if let Some(s) = &params.signature {
        sigs.push(s.clone());
        sigs.push(s.replace(' ', ""));
    }
    for s in KNOWN_SIGNATURES {
        sigs.push((*s).to_string());
    }
    for sig in &sigs {
        for (ks, is) in KNOWN_KEYPAIR_SUFFIXES {
            candidates.push((format!("{sig}{ks}"), Some(format!("{sig}{is}"))));
        }
    }
    for (k, iv) in KNOWN_KEYPAIRS {
        candidates.push(((*k).to_string(), Some((*iv).to_string())));
    }

    // 3. Serial-based keypairs
    if let Some(serial) = &params.serial {
        for (kp, ip) in KNOWN_KEYPAIR_PREFIXES {
            candidates.push((format!("{kp}{serial}"), Some(format!("{ip}{serial}"))));
        }
    }

    // 4. MAC-based keypairs
    if let Some(mac) = &params.mac {
        let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if clean.len() == 12 {
            let lower_colon = format!(
                "{}:{}:{}:{}:{}:{}",
                &clean[0..2], &clean[2..4], &clean[4..6], &clean[6..8], &clean[8..10], &clean[10..12]
            ).to_ascii_lowercase();
            candidates.push((lower_colon.clone(), Some("ZTE%FN$GponNJ025".to_string())));
            candidates.push((clean.to_ascii_lowercase(), Some("ZTE%FN$GponNJ025".to_string())));
        }
    }

    for (k, iv) in &candidates {
        if let Ok(res) = decode_config(data, Some(k), iv.as_deref()) {
            return Ok(res);
        }
    }

    Err("Auto-decode failed: no matching key/IV found for this config.bin".into())
}

fn build_type0_payload(xml: &[u8]) -> Vec<u8> {
    let z = zlib_compress_stored(xml);
    let comp_crc = crc32(&z);
    let mut type0 = Vec::with_capacity(60 + 12 + z.len());
    let mut hdr0 = Vec::with_capacity(24);
    hdr0.extend_from_slice(&PAYLOAD_MAGIC.to_be_bytes());
    hdr0.extend_from_slice(&0u32.to_be_bytes());
    hdr0.extend_from_slice(&(xml.len() as u32).to_be_bytes());
    hdr0.extend_from_slice(&(60u32 + 12 + z.len() as u32).to_be_bytes());
    hdr0.extend_from_slice(&(65536u32).to_be_bytes());
    hdr0.extend_from_slice(&comp_crc.to_be_bytes());
    let hdr_crc = crc32(&hdr0);
    type0.extend_from_slice(&hdr0);
    type0.extend_from_slice(&hdr_crc.to_be_bytes());
    type0.resize(60, 0);
    type0.extend_from_slice(&(xml.len() as u32).to_be_bytes());
    type0.extend_from_slice(&(z.len() as u32).to_be_bytes());
    type0.extend_from_slice(&0u32.to_be_bytes());
    type0.extend_from_slice(&z);
    type0
}

fn wrap_zte_container(payload: &[u8], signature: &str, include_zte_header: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let sig_bytes = signature.as_bytes();
    let full_len = payload.len() + if sig_bytes.is_empty() { 0 } else { 12 + sig_bytes.len() };
    if include_zte_header {
        for m in ZTE_MAGIC {
            out.extend_from_slice(&m.to_be_bytes());
        }
        let mut zhdr = [0u32; 28];
        zhdr[2] = 4;
        zhdr[11] = 64;
        zhdr[12] = 0x0200;
        zhdr[13] = 128;
        zhdr[14] = full_len as u32;
        for w in zhdr {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }
    if !sig_bytes.is_empty() {
        out.extend_from_slice(&SIGNATURE_MAGIC.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(sig_bytes);
    }
    out.extend_from_slice(payload);
    out
}

/// Encodes XML bytes into a ZTE `config.bin` payload (supports Type 2, Type 3, and Type 4).
pub fn encode_config(
    xml: &[u8],
    payload_type: u32,
    signature: &str,
    key: &str,
    iv: Option<&str>,
    include_zte_header: bool,
) -> Result<Vec<u8>, String> {
    let crypto = LibCrypto::load()?;
    let type0 = build_type0_payload(xml);
    let unenc_len = type0.len();

    let mut padded = type0;
    if padded.len() % 16 != 0 {
        padded.resize(padded.len() + (16 - padded.len() % 16), 0);
    }

    let (enc, block_hdr_unenc, chunk_hdr_dec) = match payload_type {
        2 => {
            let mut k_bytes = [0u8; 16];
            let raw_k = key.as_bytes();
            k_bytes[..raw_k.len().min(16)].copy_from_slice(&raw_k[..raw_k.len().min(16)]);
            let enc = crypto.aes_crypt(unsafe { (crypto.evp_aes_128_ecb)() }, &k_bytes, None, &padded, true)?;
            let enc_len = enc.len();
            (enc, 0u32, enc_len as u32)
        }
        3 | 4 => {
            let iv_str = if payload_type == 3 { key } else { iv.unwrap_or(key) };
            let k_hash = crypto.sha256_digest(key.as_bytes());
            let iv_hash = crypto.sha256_digest(iv_str.as_bytes());
            let enc = crypto.aes_crypt(
                unsafe { (crypto.evp_aes_256_cbc)() },
                &k_hash,
                Some(&iv_hash[..16]),
                &padded,
                true,
            )?;
            (enc, 0u32, unenc_len as u32)
        }
        other => return Err(format!("Unsupported encode payload type: {other}")),
    };

    let mut block = Vec::with_capacity(60 + 12 + enc.len());
    block.extend_from_slice(&PAYLOAD_MAGIC.to_be_bytes());
    block.extend_from_slice(&payload_type.to_be_bytes());
    block.extend_from_slice(&block_hdr_unenc.to_be_bytes());
    block.extend_from_slice(&(if payload_type == 2 { enc.len() as u32 + 72 } else { 0 }).to_be_bytes());
    block.extend_from_slice(&(if payload_type == 2 { 65536u32 } else { 0 }).to_be_bytes());
    block.resize(60, 0);
    block.extend_from_slice(&chunk_hdr_dec.to_be_bytes());
    block.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    block.extend_from_slice(&0u32.to_be_bytes());
    block.extend_from_slice(&enc);

    Ok(wrap_zte_container(&block, signature, include_zte_header))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_type2_h168n() {
        let xml = b"<DB><Tbl name=\"WLAN\" RowCount=\"1\"><Row No=\"0\"><DM name=\"ESSID\" val=\"TestAP\"/></Row></Tbl></DB>";
        let key = find_known_key("ZXHN H168N V3.1").expect("H168N V3.1 key");
        let encoded = encode_config(xml, 2, "ZXHN H168N V3.1", key, None, true).unwrap();
        let decoded = decode_config(&encoded, None, None).unwrap();
        assert_eq!(decoded.signature, "ZXHN H168N V3.1");
        assert_eq!(decoded.payload_type, 2);
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn roundtrip_type4_h188a() {
        let xml = b"<DB><Tbl name=\"DEV\" RowCount=\"1\"><Row No=\"0\"><DM name=\"Model\" val=\"H188A\"/></Row></Tbl></DB>";
        let encoded = encode_config(xml, 4, "H188A", "H188AKey02721401", Some("H188AIv02721401"), true).unwrap();
        let decoded = auto_decode_config(&encoded, &AutoKeygenParams::default()).unwrap();
        assert_eq!(decoded.signature, "H188A");
        assert_eq!(decoded.payload_type, 4);
        assert_eq!(decoded.used_key, "H188AKey02721401");
        assert_eq!(decoded.used_iv, "H188AIv02721401");
        assert_eq!(decoded.xml, xml);
    }
}
