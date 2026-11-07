use std::collections::HashMap;

#[derive(Clone)]
struct Call {
    ts_ns: i128,
    text: String,
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// "2026-11-06T21:43:27.793Z" -> unix nanoseconds
fn parse_iso(s: &str) -> Option<i128> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((h, f)) => (h, f),
        None => (time, "0"),
    };
    let mut tp = hms.split(':');
    let h: i128 = tp.next()?.parse().ok()?;
    let mi: i128 = tp.next()?.parse().ok()?;
    let se: i128 = tp.next()?.parse().ok()?;
    let mut fpart = frac.to_string();
    while fpart.len() < 9 {
        fpart.push('0');
    }
    let nanos: i128 = fpart[..9].parse().ok()?;
    let days = days_from_civil(y, mo, d);
    Some(((days as i128) * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000_000 + nanos)
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

fn load_calls(path: &str) -> Vec<Call> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["type"] != "message" || v["message"]["role"] != "assistant" {
            continue;
        }
        let Some(ts) = v["timestamp"].as_str().and_then(parse_iso) else { continue };
        let Some(parts) = v["message"]["content"].as_array() else { continue };
        for p in parts {
            if p["type"] != "toolCall" {
                continue;
            }
            // declared arguments are what the monitor reads; the tool result is not
            let text = format!(
                "{} {}",
                p["name"].as_str().unwrap_or(""),
                serde_json::to_string(&p["arguments"]).unwrap_or_default()
            );
            out.push(Call { ts_ns: ts, text });
        }
    }
    out.sort_by_key(|c| c.ts_ns);
    out
}

pub fn main() -> anyhow::Result<()> {
    let mut edges_path: Option<String> = None;
    let mut transcripts: HashMap<u64, String> = HashMap::new();
    let mut window_ms: i128 = 30_000;
    let mut offset: Option<i128> = None;

    let mut it = std::env::args().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--edges" => edges_path = it.next(),
            "--transcript" => {
                let spec = it.next().unwrap_or_default();
                let (ino, path) = spec.split_once('=').unwrap_or(("0", ""));
                transcripts.insert(ino.parse().unwrap_or(0), path.to_string());
            }
            "--window-ms" => window_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(window_ms),
            "--offset-ns" => offset = it.next().and_then(|v| v.parse().ok()),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let edges_path = edges_path.ok_or_else(|| anyhow::anyhow!("--edges is required"))?;
    let offset = offset.unwrap_or_else(wall_offset_ns);
    let window = window_ms * 1_000_000;

    let calls: HashMap<u64, Vec<Call>> =
        transcripts.iter().map(|(ino, p)| (*ino, load_calls(p))).collect();

    let text = std::fs::read_to_string(&edges_path)?;
    let mut total = 0usize;
    let mut detected = 0usize;
    let mut misses = Vec::new();

    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["kind"] != "edge" {
            continue;
        }
        total += 1;
        let src = v["src"].as_u64().unwrap_or(0);
        let dst = v["dst"].as_u64().unwrap_or(0);
        let path = v["path"].as_str().unwrap_or("");
        let ts = v["ts_ns"].as_u64().unwrap_or(0) as i128 + offset;
        if path.is_empty() {
            continue;
        }
        // a cross-agent monitor needs BOTH endpoints to have declared the object
        let mut sides = 0;
        for agent in [src, dst] {
            let seen = calls
                .get(&agent)
                .map(|cs| {
                    cs.iter().any(|c| {
                        (c.ts_ns - ts).abs() <= window && c.text.contains(path)
                    })
                })
                .unwrap_or(false);
            if seen {
                sides += 1;
            }
        }
        if sides == 2 {
            detected += 1;
        } else {
            misses.push(format!(
                "{{\"src\":{src},\"dst\":{dst},\"path\":\"{path}\",\"declared_sides\":{sides}}}"
            ));
        }
    }

    // inverse error: declared objects the kernel never observed for that agent
    let mut spoof_suspects = 0usize;
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["kind"] != "edge" {
            continue;
        }
        let path = v["path"].as_str().unwrap_or("");
        if path.is_empty() {
            continue;
        }
        for (ino, cs) in calls.iter() {
            let declared = cs.iter().any(|c| c.text.contains(path));
            let observed = (*ino == v["src"].as_u64().unwrap_or(0))
                || (*ino == v["dst"].as_u64().unwrap_or(0));
            if declared && !observed {
                spoof_suspects += 1;
            }
        }
    }

    let recall = if total > 0 { detected as f64 / total as f64 } else { 0.0 };
    println!(
        "{{\"kernel_edges\":{total},\"transcript_detected\":{detected},\"transcript_recall\":{recall:.3},\"window_ms\":{window_ms},\"spoof_suspects\":{spoof_suspects}}}"
    );
    for m in misses.iter().take(20) {
        eprintln!("missed {m}");
    }
    Ok(())
}
