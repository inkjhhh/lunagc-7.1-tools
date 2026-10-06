//! Local TLS front for the game SDK curl stack.
//!
//! Listens on 127.0.0.1:443 with a locally-trusted cert (SANs for the SDK
//! hosts, installed into CurrentUser\Root), terminates TLS, and forwards
//! plain HTTP to 127.0.0.1:8088 (LunaGC dispatch).
//!
//! Single-threaded HTTP-aware relay: parses Content-Length / chunked bodies
//! both ways, supports keep-alive reuse on the client connection, opens a
//! fresh backend connection per request.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const LISTEN: &str = "127.0.0.1:443";
const BACKEND: &str = "127.0.0.1:8088";
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pfx = args.get(1).map(|s| s.as_str()).unwrap_or("front.pfx");
    let pass = args.get(2).map(|s| s.as_str()).unwrap_or("lunagc");
    // Optional credential override: base64(plaintext) replaces whatever
    // ciphertext the client sends for loginByPassword. The server accepts
    // printable plaintext via its fallback path. This sidesteps client-side
    // RSA entirely (the 7.1 SDK ignores our rsa_key config).
    if let (Some(u), Some(p)) = (args.get(3), args.get(4)) {
        use std::fmt::Write as _;
        let b64 = |s: &str| {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let b = s.as_bytes();
            let mut o = String::new();
            for c in b.chunks(3) {
                let n = ((c[0] as u32) << 16)
                    | ((if c.len() > 1 { c[1] } else { 0 } as u32) << 8)
                    | (if c.len() > 2 { c[2] } else { 0 } as u32);
                for i in 0..4 {
                    if i <= c.len() {
                        let _ = write!(o, "{}", T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                    } else {
                        let _ = write!(o, "=");
                    }
                }
            }
            o
        };
        std::env::set_var("LUNAGC_PLAINTEXT_USER", b64(u));
        std::env::set_var("LUNAGC_PLAINTEXT_PASS", b64(p));
        println!("[tlsfront] credential override active");
    }

    let der = std::fs::read(pfx).expect("read pfx");
    let id = native_tls::Identity::from_pkcs12(&der, pass).expect("parse pfx");
    let acceptor = native_tls::TlsAcceptor::new(id).expect("tls acceptor");

    let listener = TcpListener::bind(LISTEN).expect("bind 443");
    println!("[tlsfront] listening on {LISTEN}, backend {BACKEND}");

    for incoming in listener.incoming() {
        let Ok(tcp) = incoming else { continue };
        let Ok(tls) = acceptor.accept(tcp) else {
            println!("[tlsfront] TLS handshake failed (client rejected cert?)");
            continue;
        };
        std::thread::spawn(move || handle(tls));
    }
}

fn read_more<R: Read>(r: &mut R, raw: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 8192];
    match r.read(&mut chunk) {
        Ok(0) => false,
        Ok(k) => {
            raw.extend_from_slice(&chunk[..k]);
            true
        }
        Err(_) => false,
    }
}

/// Read until end of HTTP head (\r\n\r\n), cap 64KB. None on EOF/error.
fn read_head<R: Read>(r: &mut R) -> Option<Vec<u8>> {
    let mut raw: Vec<u8> = Vec::new();
    loop {
        if !read_more(r, &mut raw) {
            return if raw.is_empty() { None } else { Some(raw) };
        }
        if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 65536 {
            return Some(raw);
        }
    }
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Read a full HTTP message (head already in `raw`), following
/// Content-Length or chunked framing. Returns the complete bytes.
fn read_message<R: Read>(r: &mut R, mut raw: Vec<u8>, is_request: bool) -> Option<Vec<u8>> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head_str = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let first = head_str.lines().next().unwrap_or("");

    let no_body = if is_request {
        !(first.starts_with("POST") || first.starts_with("PUT") || first.starts_with("PATCH"))
    } else {
        first.contains(" 204 ") || first.contains(" 304 ")
    };
    if no_body {
        raw.truncate(head_end);
        return Some(raw);
    }

    if let Some(cl) = header_value(&head_str, "content-length") {
        if let Ok(n) = cl.parse::<usize>() {
            while raw.len() < head_end + n {
                if !read_more(r, &mut raw) {
                    break;
                }
            }
            let want = head_end + n.min(raw.len().saturating_sub(head_end));
            raw.truncate(want);
            return Some(raw);
        }
    }

    if header_value(&head_str, "transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        loop {
            if !read_more(r, &mut raw) {
                break;
            }
            if raw.ends_with(b"0\r\n\r\n") || raw.len() > 32 * 1024 * 1024 {
                break;
            }
        }
        return Some(raw);
    }

    // Unknown length: read until close.
    while read_more(r, &mut raw) {}
    Some(raw)
}

/// Replace RSA ciphertexts in a loginByPassword body with base64(plaintext)
/// from LUNAGC_PLAINTEXT_USER/PASS (set from argv). Fixes Content-Length.
/// Returns the (possibly rewritten) full request bytes.
fn rewrite_login_body(req: Vec<u8>) -> Vec<u8> {
    let (Ok(user), Ok(pass)) = (
        std::env::var("LUNAGC_PLAINTEXT_USER"),
        std::env::var("LUNAGC_PLAINTEXT_PASS"),
    ) else {
        return req;
    };
    let head_end = match req.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return req,
    };
    let mut body = String::from_utf8_lossy(&req[head_end..]).into_owned();
    if !body.contains("loginByPassword") && !body.contains("account") {
        // path-based check instead: only rewrite bodies carrying credentials
        if !body.contains("\"password\"") {
            return req;
        }
    }
    let mut changed = false;
    for (field, val) in [("\"account\"", user.as_str()), ("\"password\"", pass.as_str())] {
        if let Some(fs) = body.find(field) {
            let vs = match body[fs..].find(':') {
                Some(o) => fs + o + 1,
                None => continue,
            };
            let q1 = match body[vs..].find('"') {
                Some(o) => vs + o + 1,
                None => continue,
            };
            let q2 = match body[q1..].find('"') {
                Some(o) => q1 + o,
                None => continue,
            };
            body.replace_range(q1..q2, val);
            changed = true;
        }
    }
    if !changed {
        return req;
    }
    println!("[tlsfront] rewrote login ciphertext -> plaintext creds");
    let mut out = req[..head_end].to_vec();
    // fix Content-Length header
    let mut head = String::from_utf8_lossy(&out).into_owned();
    let new_len = body.len();
    let mut fixed = false;
    let mut res = String::new();
    for line in head.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            res.push_str(&format!("Content-Length: {new_len}\r\n"));
            fixed = true;
        } else {
            res.push_str(line);
            res.push_str("\r\n");
        }
    }
    if !fixed {
        return req;
    }
    out = res.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn handle(mut tls: native_tls::TlsStream<TcpStream>) {
    let _ = tls.get_ref().set_read_timeout(Some(IDLE_TIMEOUT));

    loop {
        let Some(raw) = read_head(&mut tls) else {
            return;
        };
        let Some(req) = read_message(&mut tls, raw, true) else {
            return;
        };
        let (first, host, want_close) = {
            let head_str = String::from_utf8_lossy(&req);
            let first = head_str.lines().next().unwrap_or("").to_string();
            let host = head_str
                .lines()
                .find(|l| l.to_lowercase().starts_with("host:"))
                .unwrap_or("Host: ?")
                .to_string();
            let want_close = head_str.to_lowercase().contains("connection: close");
            (first, host, want_close)
        };
        println!("[tlsfront] {first} | {host}");

        // Dump login bodies for offline crypto analysis.
        if first.contains("loginByPassword") || first.contains("verifySToken") {
            let dump_path = std::env::temp_dir().join("login_body.bin");
            let _ = std::fs::write(&dump_path, &req);
        }

        let req = rewrite_login_body(req);

        let mut back = match TcpStream::connect(BACKEND) {
            Ok(s) => s,
            Err(e) => {
                println!("[tlsfront] backend connect failed: {e}");
                return;
            }
        };
        if back.write_all(&req).is_err() {
            return;
        }
        let _ = back.set_read_timeout(Some(Duration::from_secs(30)));
        let Some(braw) = read_head(&mut back) else {
            return;
        };
        let Some(resp) = read_message(&mut back, braw, false) else {
            return;
        };
        if tls.write_all(&resp).is_err() {
            return;
        }
        let _ = tls.flush();

        if want_close {
            return;
        }
    }
}
