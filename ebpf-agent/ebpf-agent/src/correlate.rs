use std::collections::{HashMap, HashSet, VecDeque};

const O_WRITE: u64 = 0o1 | 0o2 | 0o100 | 0o1000;
const MAX_OBS_PER_OBJECT: usize = 256;

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Mutate,
    Sense,
}

#[derive(Clone, Copy)]
struct Obs {
    ts: u64,
    agent: u64,
    tgid: u64,
    nr: u64,
    role: Role,
}

#[derive(Default)]
struct Obj {
    path: String,
    recent: VecDeque<Obs>,
    first_ts: u64,
    agents: HashSet<u64>,
}

pub struct Correlator {
    objs: HashMap<(u64, u64), Obj>,
    by_path: HashMap<(u64, String), (u64, u64)>,
    seen: HashSet<(u64, u64, u64, u64, u64)>,
    window_ns: u64,
    pub edges: usize,
}

fn is_mutator(nr: u64, a: &[u64; 6]) -> bool {
    match nr {
        257 | 2 => a[2] & O_WRITE != 0,
        85 | 76 | 77 => true,
        82 | 264 | 316 => true,
        87 | 263 | 84 => true,
        83 | 258 | 259 | 133 => true,
        86 | 88 | 265 | 266 => true,
        90 | 91 | 268 => true,
        92 | 93 | 94 | 260 => true,
        188 | 189 | 190 | 197 | 198 | 199 => true,
        280 | 261 => true,
        1 | 18 | 20 => true,
        74 | 75 => true,
        49 => true, // bind: creates the socket inode that connect later resolves
        _ => false,
    }
}

impl Correlator {
    pub fn new(window_ms: u64) -> Self {
        Self {
            objs: HashMap::new(),
            by_path: HashMap::new(),
            seen: HashSet::new(),
            window_ns: window_ms * 1_000_000,
            edges: 0,
        }
    }

    pub fn ingest(&mut self, line: &str) -> Vec<String> {
        let mut out = Vec::new();
        if !line.starts_with("{\"kind\":\"event\"") {
            return out;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return out;
        };

        let dev = v["dev"].as_u64().unwrap_or(0);
        let ino = v["ino"].as_u64().unwrap_or(0);
        let path = v["path"].as_str().unwrap_or("").to_string();
        let nr = v["nr"].as_u64().unwrap_or(0);
        let ts = v["ts_ns"].as_u64().unwrap_or(0);
        let agent = v["agent"].as_u64().unwrap_or(0);
        let tgid = v["tgid"].as_u64().unwrap_or(0);
        let pdev = v["pdev"].as_u64().unwrap_or(0);
        let pino = v["pino"].as_u64().unwrap_or(0);
        let adev = v["aux_dev"].as_u64().unwrap_or(0);
        let aino = v["aux_ino"].as_u64().unwrap_or(0);
        let aux_path = v["aux"].as_str().unwrap_or("").to_string();
        let mut a = [0u64; 6];
        if let Some(arr) = v["args"].as_array() {
            for (i, x) in arr.iter().take(6).enumerate() {
                a[i] = x.as_u64().unwrap_or(0);
            }
        }

        // agent-scoped: a path-only cache lets one agent's resolved inode stand in
        // for another's unresolved one, inventing a shared object between them
        let key = if dev != 0 {
            (dev, ino)
        } else if let Some(k) = self.by_path.get(&(agent, path.clone())) {
            *k
        } else {
            return out;
        };
        if dev != 0 && !path.is_empty() {
            self.by_path.insert((agent, path.clone()), key);
        }

        let role = if is_mutator(nr, &a) { Role::Mutate } else { Role::Sense };
        let mut targets: Vec<((u64, u64), Obs, String)> =
            vec![(key, Obs { ts, agent, tgid, nr, role }, path.clone())];

        let dir_mutating = match nr {
            257 | 2 => a[2] & 0o100 != 0,
            _ => matches!(nr, 85 | 83 | 258 | 259 | 87 | 263 | 84 | 82 | 264 | 316 | 86 | 88 | 265 | 266),
        };
        if dir_mutating && pdev != 0 && (pdev, pino) != key {
            let dir_path = path
                .rsplit_once('/')
                .map(|(d, _)| if d.is_empty() { "/" } else { d })
                .unwrap_or("")
                .to_string();
            targets.push(((pdev, pino), Obs { ts, agent, tgid, nr, role: Role::Mutate }, dir_path));
        }

        for (key, obs, disp) in targets {
            let obj = self.objs.entry(key).or_default();
            if obj.path.is_empty() && !disp.is_empty() {
                obj.path = disp;
            }
            if obj.first_ts == 0 {
                obj.first_ts = ts;
            }
            obj.agents.insert(obs.agent);

            if matches!(nr, 87 | 263 | 84) {
                out.push(format!(
                    "{{\"kind\":\"scrub\",\"ts_ns\":{ts},\"agent\":{},\"dev\":{},\"ino\":{},\"path\":\"{}\"}}",
                    obs.agent,
                    key.0,
                    key.1,
                    obj.path.replace('"', "\\\"")
                ));
            }

            let window = self.window_ns;
            let fanout = obj.agents.len() as u64;
            let age_ns = ts.saturating_sub(obj.first_ts);
            let mut emitted = Vec::new();
            for other in obj.recent.iter() {
                if other.agent == obs.agent {
                    continue;
                }
                let (m, s) = match (other.role, obs.role) {
                    (Role::Mutate, Role::Sense) => (*other, obs),
                    (Role::Sense, Role::Mutate) => (obs, *other),
                    _ => continue,
                };
                if s.ts < m.ts || s.ts - m.ts > window {
                    continue;
                }
                let dedupe = (m.agent, s.agent, key.0, key.1, m.ts);
                if !self.seen.insert(dedupe) {
                    continue;
                }
                self.edges += 1;
                emitted.push(format!(
                    "{{\"kind\":\"edge\",\"src\":{},\"dst\":{},\"src_tgid\":{},\"dst_tgid\":{},\"dev\":{},\"ino\":{},\"dt_ns\":{},\"src_nr\":{},\"dst_nr\":{},\"fanout\":{},\"age_ns\":{},\"ts_ns\":{},\"path\":\"{}\"}}",
                    m.agent,
                    s.agent,
                    m.tgid,
                    s.tgid,
                    key.0,
                    key.1,
                    s.ts - m.ts,
                    m.nr,
                    s.nr,
                    fanout,
                    age_ns,
                    s.ts,
                    obj.path.replace('"', "\\\"")
                ));
            }
            out.extend(emitted);

            obj.recent.push_back(obs);
            while obj.recent.len() > MAX_OBS_PER_OBJECT {
                obj.recent.pop_front();
            }
            while let Some(front) = obj.recent.front() {
                if ts.saturating_sub(front.ts) > window && obj.recent.len() > 8 {
                    obj.recent.pop_front();
                } else {
                    break;
                }
            }
        }
        out
    }
}
