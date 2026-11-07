use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn wire(method: &str, path: &str, host: &str, port: u16, auth: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect((host, port))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    s.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())?;
    let mut resp = String::new();
    std::io::Read::read_to_string(&mut s, &mut resp)?;
    let code = resp.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((code, resp))
}

fn wall_offset_ns() -> i128 {
    let mut rt = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut mono = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut rt);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
    }
    (rt.tv_sec as i128 * 1_000_000_000 + rt.tv_nsec as i128)
        - (mono.tv_sec as i128 * 1_000_000_000 + mono.tv_nsec as i128)
}

fn iso8601(unix_ns: u64) -> String {
    let secs = unix_ns / 1_000_000_000;
    let nanos = unix_ns % 1_000_000_000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mth <= 2 { y + 1 } else { y };
    format!("{yr:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}.{nanos:09}Z")
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct Sink {
    host: String,
    port: u16,
    auth: String,
    index: String,
    deadline: String,
    offset: i128,
    pub shipped: usize,
    pub failed: usize,
}

impl Sink {
    pub fn new(es: &str, user: &str, pass: &str, index: &str, dead_letter: &str) -> Self {
        let hp = es.trim_start_matches("http://").trim_end_matches('/');
        let (host, port) = match hp.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(9200)),
            None => (hp.to_string(), 9200),
        };
        Self {
            host,
            port,
            auth: b64(format!("{user}:{pass}").as_bytes()),
            index: index.to_string(),
            deadline: dead_letter.to_string(),
            offset: wall_offset_ns(),
            shipped: 0,
            failed: 0,
        }
    }

    pub fn index(&self) -> &str {
        &self.index
    }

    pub fn send(&mut self, lines: &[String]) -> anyhow::Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let mut body = String::new();
        for l in lines {
            let Ok(mut v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
            if v.get("@timestamp").is_none() {
                if let Some(ts) = v["ts_ns"].as_u64() {
                    let wall = ts as i128 + self.offset;
                    if wall > 0 {
                        v["@timestamp"] = serde_json::json!(iso8601(wall as u64));
                    }
                }
            }
            let l = &v.to_string();
            let kind = v["kind"].as_str().unwrap_or("x");
            let agent = v["agent"].as_u64().or_else(|| v["src"].as_u64()).unwrap_or(0);
            let ino = v["ino"].as_u64().unwrap_or(0);
            // records without an inode (reasoning, desync) need a content-derived
            // discriminator or several parts of one message overwrite each other
            let salt = fnv(l);
            let id = format!("{kind}-{}-{agent}-{ino}-{salt}", v["ts_ns"].as_u64().unwrap_or(0));
            body.push_str(&format!(
                "{{\"index\":{{\"_index\":\"{}\",\"_id\":\"{id}\"}}}}\n{l}\n",
                self.index
            ));
        }
        if body.is_empty() {
            return Ok(());
        }
        match wire("POST", "/_bulk", &self.host, self.port, &self.auth, &body) {
            Ok((200, resp)) if !resp.contains("\"errors\":true") => self.shipped += lines.len(),
            other => {
                self.failed += lines.len();
                if let Ok(mut dl) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.deadline)
                {
                    for l in lines {
                        let _ = writeln!(dl, "{l}");
                    }
                }
                match other {
                    Ok((code, resp)) => eprintln!("bulk: http {code} ({})", &resp[..resp.len().min(120)]),
                    Err(e) => eprintln!("bulk: {e}"),
                }
            }
        }
        Ok(())
    }
}

pub fn spawn_shipper(sink: Sink, rx: Receiver<String>) -> std::thread::JoinHandle<Sink> {
    std::thread::spawn(move || {
        let mut sink = sink;
        let mut batch: Vec<String> = Vec::new();
        let mut last = std::time::Instant::now();
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(300)) {
                Ok(line) => {
                    batch.push(line);
                    while let Ok(l) = rx.try_recv() {
                        batch.push(l);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = sink.send(&batch);
                    return sink;
                }
            }
            if !batch.is_empty() && (batch.len() >= 200 || last.elapsed().as_millis() >= 300) {
                let _ = sink.send(&batch);
                batch.clear();
                last = std::time::Instant::now();
            }
        }
    })
}

pub fn offer(tx: &SyncSender<String>, line: String) -> bool {
    match tx.try_send(line) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => false,
        Err(TrySendError::Disconnected(_)) => false,
    }
}

pub fn init(es: &str, user: &str, pass: &str) -> anyhow::Result<()> {
    let hp = es.trim_start_matches("http://").trim_end_matches('/');
    let (host, port) = match hp.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(9200)),
        None => (hp.to_string(), 9200),
    };
    let auth = b64(format!("{user}:{pass}").as_bytes());
    let body = r#"{"index_patterns":["cdr-*"],"template":{"settings":{"number_of_shards":1,"number_of_replicas":0,"refresh_interval":"5s"},"mappings":{"dynamic":false,"properties":{"@timestamp":{"type":"date"},"kind":{"type":"keyword"},"agent":{"type":"keyword"},"src":{"type":"keyword"},"dst":{"type":"keyword"},"src_tgid":{"type":"keyword"},"dst_tgid":{"type":"keyword"},"dev":{"type":"keyword"},"ino":{"type":"keyword"},"dt_ns":{"type":"keyword"},"fanout":{"type":"long"},"age_ns":{"type":"long"},"src_nr":{"type":"long"},"dst_nr":{"type":"long"},"ts_ns":{"type":"keyword"},"path":{"type":"keyword"},"verdict":{"type":"keyword"},"class":{"type":"keyword"},"declared":{"type":"keyword"},"observed":{"type":"keyword"},"src_declared":{"type":"keyword"},"dst_declared":{"type":"keyword"},"unaccounted":{"type":"keyword"},"variant":{"type":"keyword"},"trust":{"type":"keyword"},"text":{"type":"text"}}}}}"#;
    let (code, resp) = wire("PUT", "/_index_template/cdr", &host, port, &auth, body)?;
    eprintln!("init: template http {code} {}", &resp[..resp.len().min(120)]);
    Ok(())
}
