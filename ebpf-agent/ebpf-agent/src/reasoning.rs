use crate::es;

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn parse_iso(s: &str) -> Option<i128> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut tp = hms.split(':');
    let h: i128 = tp.next()?.parse().ok()?;
    let mi: i128 = tp.next()?.parse().ok()?;
    let se: i128 = tp.next()?.parse().ok()?;
    let mut f = frac.to_string();
    while f.len() < 9 {
        f.push('0');
    }
    let nanos: i128 = f[..9].parse().ok()?;
    Some(((days_from_civil(y, mo, d) as i128) * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000_000 + nanos)
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

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn ingest() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let opt = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let index = opt("--index", "cdr-events");
    let es_url = opt("--es", "http://127.0.0.1:9200");
    let pass_file = opt("--password-file", "/home/mikey/.cdr-es-pass");
    let dead_letter = opt("--dead-letter", "es-dead.ndjson");
    let cap: usize = opt("--max-chars", "4000").parse().unwrap_or(4000);
    let offset = wall_offset_ns();

    let mut transcripts: Vec<(u64, String)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--transcript" {
            if let Some(spec) = args.get(i + 1) {
                if let Some((ino, path)) = spec.split_once('=') {
                    transcripts.push((ino.parse().unwrap_or(0), path.to_string()));
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    if transcripts.is_empty() {
        anyhow::bail!("--transcript <agent_ino>=<session.jsonl> is required");
    }

    let pass = std::fs::read_to_string(&pass_file).unwrap_or_default();
    let mut sink = es::Sink::new(&es_url, "cdr", pass.trim(), &index, &dead_letter);
    let mut batch: Vec<String> = Vec::new();
    let mut count = 0usize;

    for (agent, path) in &transcripts {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if v["type"] != "message" || v["message"]["role"] != "assistant" {
                continue;
            }
            let Some(ts) = v["timestamp"].as_str().and_then(parse_iso) else { continue };
            let Some(parts) = v["message"]["content"].as_array() else { continue };
            for p in parts {
                if p["type"] != "thinking" {
                    continue;
                }
                let Some(thinking) = p["thinking"].as_str() else { continue };
                let mut body: String = thinking.chars().take(cap).collect();
                if body.is_empty() {
                    continue;
                }
                if thinking.chars().count() > cap {
                    body.push_str("…[truncated]");
                }
                let mono = (ts - offset).max(0) as u64;
                batch.push(format!(
                    "{{\"kind\":\"reasoning\",\"trust\":\"agent-authored\",\"ts_ns\":{mono},\"agent\":{agent},\"text\":\"{}\"}}",
                    escape(&body)
                ));
                count += 1;
                if batch.len() >= 200 {
                    sink.send(&batch)?;
                    batch.clear();
                }
            }
        }
    }
    sink.send(&batch)?;
    eprintln!("reasoning: {count} records -> {} (shipped={})", sink.index(), sink.shipped);
    Ok(())
}
