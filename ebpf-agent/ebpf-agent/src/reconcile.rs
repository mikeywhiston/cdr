use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct Call {
    ts: i128,
    command: String,
}

#[derive(Clone)]
struct ExecNode {
    agent: u64,
    tgid: u64,
    ppid: u64,
    ts: u64,
    path: String,
    argv: Vec<String>,
}

impl ExecNode {
    fn effective(&self) -> String {
        let a = &self.argv;
        if a.len() >= 3 && (a[0].ends_with("sh") || a[0].ends_with("bash")) && a[1] == "-c" {
            return norm(&a[2]);
        }
        norm(&a.join(" "))
    }
}

const NR_EXECVE: u64 = 59;
const MAX_DEPTH: usize = 16;

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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
            let Some(cmd) = p["arguments"]["command"].as_str() else { continue };
            out.push(Call { ts, command: cmd.trim().to_string() });
        }
    }
    out.sort_by_key(|c| c.ts);
    out
}

fn base(tok: &str) -> &str {
    tok.rsplit('/').next().unwrap_or(tok)
}

fn same_command(declared: &str, effective: &str) -> bool {
    if declared == effective {
        return true;
    }
    let d: Vec<&str> = declared.split_whitespace().collect();
    let e: Vec<&str> = effective.split_whitespace().collect();
    if d.is_empty() || e.is_empty() || d.len() != e.len() {
        return false;
    }
    base(d[0]) == base(e[0]) && d[1..] == e[1..]
}

fn is_snapshot(n: &ExecNode) -> bool {
    n.argv.join(" ").contains("omp-shell-snapshots")
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

struct Tree {
    nodes: Vec<ExecNode>,
    by_tgid: HashMap<u64, Vec<usize>>,
    forks: HashMap<u64, u64>,
    kids: HashMap<u64, Vec<u64>>,
}

impl Tree {
    fn load(path: &str) -> Self {
        let mut forks: HashMap<u64, u64> = HashMap::new();
        let mut nodes: Vec<ExecNode> = Vec::new();
        let mut argv: HashMap<(u64, u64), Vec<(u16, String)>> = HashMap::new();
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self {
                nodes,
                by_tgid: HashMap::new(),
                forks,
                kids: HashMap::new(),
            };
        };

        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if v["kind"] == "fork" {
                let child = v["tgid"].as_u64().unwrap_or(0);
                let parent = v["ppid"].as_u64().unwrap_or(0);
                if child != 0 && parent != 0 {
                    forks.entry(child).or_insert(parent);
                }
            }
        }

        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            match v["kind"].as_str().unwrap_or("") {
                "argv" => {
                    if v["slot"].as_u64().unwrap_or(0) != 1 {
                        continue;
                    }
                    let k = (v["ts_ns"].as_u64().unwrap_or(0), v["tgid"].as_u64().unwrap_or(0));
                    argv.entry(k).or_default().push((
                        v["i"].as_u64().unwrap_or(0) as u16,
                        v["arg"].as_str().unwrap_or("").to_string(),
                    ));
                }
                "event" => {
                    if v["nr"].as_u64().unwrap_or(0) != NR_EXECVE {
                        continue;
                    }
                    let tgid = v["tgid"].as_u64().unwrap_or(0);
                    nodes.push(ExecNode {
                        agent: v["agent"].as_u64().unwrap_or(0),
                        tgid,
                        ppid: forks.get(&tgid).copied().unwrap_or(v["ppid"].as_u64().unwrap_or(0)),
                        ts: v["ts_ns"].as_u64().unwrap_or(0),
                        path: v["path"].as_str().unwrap_or("").to_string(),
                        argv: Vec::new(),
                    });
                }
                _ => {}
            }
        }

        for n in nodes.iter_mut() {
            if let Some(mut parts) = argv.remove(&(n.ts, n.tgid)) {
                parts.sort_by_key(|(i, _)| *i);
                n.argv = parts.into_iter().map(|(_, a)| a).collect();
            }
        }

        let mut by_tgid: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            by_tgid.entry(n.tgid).or_default().push(i);
        }
        for v in by_tgid.values_mut() {
            v.sort_by_key(|i| nodes[*i].ts);
        }

        let mut kids: HashMap<u64, Vec<u64>> = HashMap::new();
        for (child, parent) in &forks {
            kids.entry(*parent).or_default().push(*child);
        }
        for n in &nodes {
            if n.ppid != 0 && !forks.contains_key(&n.tgid) {
                kids.entry(n.ppid).or_default().push(n.tgid);
            }
        }

        Self { nodes, by_tgid, forks, kids }
    }

    fn parent_of(&self, tgid: u64) -> Option<u64> {
        if let Some(p) = self.forks.get(&tgid) {
            return Some(*p);
        }
        self.by_tgid
            .get(&tgid)
            .and_then(|v| v.first())
            .map(|i| self.nodes[*i].ppid)
            .filter(|p| *p != 0 && *p != tgid)
    }

    fn node_for(&self, tgid: u64) -> Option<usize> {
        self.by_tgid.get(&tgid).and_then(|v| v.first().copied())
    }

    fn latest_for(&self, tgid: u64, ts: u64) -> Option<usize> {
        let list = self.by_tgid.get(&tgid)?;
        list.iter()
            .take_while(|i| self.nodes[**i].ts <= ts)
            .last()
            .copied()
            .or_else(|| list.first().copied())
    }

    fn ancestor(&self, tgid: u64, ts: u64) -> Option<usize> {
        let mut cur = tgid;
        for _ in 0..MAX_DEPTH {
            if let Some(i) = self.latest_for(cur, ts) {
                return Some(i);
            }
            cur = self.parent_of(cur)?;
        }
        None
    }

    fn noise_nodes(&self) -> Vec<bool> {
        let mut noise = vec![false; self.nodes.len()];

        for (i, n) in self.nodes.iter().enumerate() {
            if !n.path.ends_with("/omp") {
                continue;
            }
            noise[i] = true;
            let mut cur = n.tgid;
            for _ in 0..MAX_DEPTH {
                match self.parent_of(cur) {
                    Some(p) => {
                        if let Some(pi) = self.node_for(p) {
                            noise[pi] = true;
                        }
                        cur = p;
                    }
                    None => break,
                }
            }
        }

        for i in 0..self.nodes.len() {
            if !is_snapshot(&self.nodes[i]) {
                continue;
            }
            noise[i] = true;
            let mut stack = vec![self.nodes[i].tgid];
            let mut seen: HashSet<u64> = HashSet::new();
            while let Some(t) = stack.pop() {
                if !seen.insert(t) {
                    continue;
                }
                for k in self.kids.get(&t).cloned().unwrap_or_default() {
                    if let Some(di) = self.node_for(k) {
                        noise[di] = true;
                    }
                    stack.push(k);
                }
            }
        }

        noise
    }

    fn owner(&self, idx: usize, declared: &HashMap<usize, String>) -> Option<String> {
        if idx >= self.nodes.len() {
            return None;
        }
        if let Some(c) = declared.get(&idx) {
            return Some(c.clone());
        }
        let mut cur = self.nodes[idx].tgid;
        for _ in 0..MAX_DEPTH {
            cur = self.parent_of(cur)?;
            if let Some(pi) = self.node_for(cur) {
                if let Some(c) = declared.get(&pi) {
                    return Some(c.clone());
                }
            }
        }
        None
    }

    fn unaccounted(&self, agent: u64, matched: &HashSet<usize>) -> Vec<String> {
        let noise = self.noise_nodes();
        let declared: HashMap<usize, String> = matched
            .iter()
            .map(|i| (*i, self.nodes[*i].effective()))
            .collect();
        let mut out: Vec<String> = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if matched.contains(&i) || noise[i] || n.agent != agent || n.argv.is_empty() {
                continue;
            }
            if self.owner(i, &declared).is_some() {
                continue;
            }
            let cmd = n.effective();
            if cmd.is_empty() || out.contains(&cmd) {
                continue;
            }
            out.push(cmd);
        }
        out
    }
}

pub fn reconcile() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let opt = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let events = opt("--events", "events.jsonl");
    let offset: i128 = opt("--offset-ns", "").parse().unwrap_or_else(|_| wall_offset_ns());
    let edges_path = args.iter().position(|a| a == "--edges").and_then(|i| args.get(i + 1)).cloned();
    let policy_path = args.iter().position(|a| a == "--policy").and_then(|i| args.get(i + 1)).cloned();
    let allow: Vec<String> = policy_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| {
            v["allow"].as_array().map(|a| {
                a.iter()
                    .filter_map(|e| {
                        e.as_str()
                            .map(str::to_string)
                            .or_else(|| e["path"].as_str().map(str::to_string))
                    })
                    .collect()
            })
        })
        .unwrap_or_default();

    let allowed = |path: &str| -> bool {
        let p = path.trim_end_matches('/');
        allow.iter().any(|a| {
            let a = a.trim_end_matches('/');
            p == a || p.starts_with(&format!("{a}/"))
        })
    };

    let variant = args
        .iter()
        .position(|a| a == "--variant")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "honest".to_string());

    let mut transcripts: HashMap<u64, String> = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--transcript" {
            if let Some(spec) = args.get(i + 1) {
                if let Some((ino, path)) = spec.split_once('=') {
                    transcripts.insert(ino.parse().unwrap_or(0), path.to_string());
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    let index = args
        .iter()
        .position(|a| a == "--index")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "cdr-edges".to_string());
    let es_url = args.iter().position(|a| a == "--es").and_then(|i| args.get(i + 1)).cloned();
    let pass_file = args
        .iter()
        .position(|a| a == "--password-file")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "/home/mikey/.cdr-es-pass".to_string());
    let mut records: Vec<String> = Vec::new();
    macro_rules! out {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            println!("{line}");
            records.push(line);
        }};
    }

    let tree = Tree::load(&events);
    let mut declared: HashMap<usize, String> = HashMap::new();
    let mut matched_total = 0usize;
    let mut mismatch_total = 0usize;
    let mut omission_total = 0usize;

    for (agent, path) in &transcripts {
        let calls = load_calls(path);
        let mut matched_nodes: HashSet<usize> = HashSet::new();

        for call in &calls {
            let want = norm(&call.command);
            let hit = tree
                .nodes
                .iter()
                .position(|n| n.agent == *agent && same_command(&want, &n.effective()));
            match hit {
                Some(idx) => {
                    matched_total += 1;
                    matched_nodes.insert(idx);
                    declared.insert(idx, tree.nodes[idx].effective());
                    out!(
                        "{{\"kind\":\"desync\",\"class\":\"match\",\"variant\":\"{variant}\",\"agent\":{agent},\"ts_ns\":{},\"declared\":\"{}\",\"observed\":\"{}\",\"tgid\":{}}}",
                        (call.ts - offset).max(0),
                        escape(&call.command),
                        escape(&tree.nodes[idx].effective()),
                        tree.nodes[idx].tgid
                    );
                }
                None => {
                    let has_nodes = tree.nodes.iter().any(|n| n.agent == *agent);
                    if !has_nodes {
                        omission_total += 1;
                        println!(
                            "{{\"kind\":\"desync\",\"class\":\"omission\",\"agent\":{agent},\"ts_ns\":{},\"declared\":\"{}\"}}",
                            (call.ts - offset).max(0),
                            escape(&call.command)
                        );
                    } else {
                        mismatch_total += 1;
                        let unacc = tree.unaccounted(*agent, &matched_nodes);
                        let list: Vec<String> =
                            unacc.iter().map(|c| format!("\"{}\"", escape(c))).collect();
                        out!(
                            "{{\"kind\":\"desync\",\"class\":\"mismatch\",\"variant\":\"{variant}\",\"agent\":{agent},\"ts_ns\":{},\"declared\":\"{}\",\"unaccounted\":[{}]}}",
                            (call.ts - offset).max(0),
                            escape(&call.command),
                            list.join(",")
                        );
                    }
                }
            }
        }

        let unacc = tree.unaccounted(*agent, &matched_nodes);
        let unacc_ts = calls.last().map(|c| c.ts - offset).unwrap_or(0);
        if !unacc.is_empty() {
            let list: Vec<String> = unacc.iter().map(|c| format!("\"{}\"", escape(c))).collect();
            out!(
                "{{\"kind\":\"desync\",\"class\":\"surplus\",\"variant\":\"{variant}\",\"agent\":{agent},\"ts_ns\":{},\"unaccounted\":[{}]}}",
                (unacc_ts).max(0),
                list.join(",")
            );
        }
    }

    if let Some(ep) = &edges_path {
        if let Ok(text) = std::fs::read_to_string(ep) {
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                if v["kind"] != "edge" {
                    continue;
                }
                let ts = v["ts_ns"].as_u64().unwrap_or(0);
                let mut sides = Vec::new();
                for key in ["src_tgid", "dst_tgid"] {
                    let tgid = v[key].as_u64().unwrap_or(0);
                    let who = tree
                        .ancestor(tgid, ts)
                        .and_then(|idx| tree.owner(idx, &declared))
                        .unwrap_or_else(|| "unaccounted".to_string());
                    sides.push(format!("\"{}\"", escape(&who)));
                }
                let ep = v["path"].as_str().unwrap_or("");
                let verdict = if allowed(ep) { "sanctioned" } else { "unsanctioned" };
                out!(
                    "{{\"kind\":\"attribution\",\"variant\":\"{variant}\",\"ts_ns\":{},\"dev\":{},\"ino\":{},\"path\":\"{}\",\"src_declared\":{},\"dst_declared\":{},\"verdict\":\"{verdict}\"}}",
                    ts,
                    v["dev"].as_u64().unwrap_or(0),
                    v["ino"].as_u64().unwrap_or(0),
                    escape(ep),
                    sides[0],
                    sides[1]
                );
            }
        }
    }

    if let Some(url) = es_url {
        let pass = std::fs::read_to_string(&pass_file).unwrap_or_default();
        let mut sink = crate::es::Sink::new(&url, "cdr", pass.trim(), &index, "desync-dead.ndjson");
        sink.send(&records)?;
        eprintln!(
            "desync: shipped={} failed={}",
            sink.shipped, sink.failed
        );
    }

    eprintln!("desync: matched={matched_total} mismatch={mismatch_total} omission={omission_total}");
    Ok(())
}
