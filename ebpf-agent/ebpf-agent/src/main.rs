use std::collections::HashMap as StdHashMap;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use aya::maps::{HashMap, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use log::{info, warn};
mod correlate;
mod baseline;
mod reasoning;
mod reconcile;
mod score;
mod es;

use std::fs::File;
use std::io::{BufWriter, Write};
use ebpf_agent_common::{Event, PayloadHeader, MAX_AUX, MAX_COMM, MAX_PATH, PAYLOAD_KIND_ARGV};

static TESTBED_SLICE: &str = "/sys/fs/cgroup/swarm_adr.slice";

// fn syscall_numbers() -> Vec<(String, u16)> {
//     const HEADERS: [&str; 2] = [
//         "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
//         "/usr/include/asm/unistd_64.h"
//     ];
//
//     for path in HEADERS {
//         let Ok(text) = std::fs::read_to_string(path) else { continue };
//         let mut out = Vec::new();
//         for line in text.lines() {
//             let Some(rest) = line.strip_prefix("#define _NR_") else { continue };
//             let mut it = rest.split_whitespace();
//             let (Some(name), Some(nr)) = (it.next(), it.next()) else { continue };
//             if let Ok(nr) = nr.parse::<u16>() {
//                 out.push((name.to_string(), nr));
//             }
//         }
//         if !out.is_empty() {
//             return out;
//         }
//     }
//     Vec::new()
// }

fn syscall_numbers() -> Vec<(String, u16)> {
    syscalls::Sysno::iter()
        .filter_map(|n| u16::try_from(n.id()).ok().map(|nr| (n.name().to_string(), nr)))
        .collect()
}

/// (syscall nr, arg index) for calls whose target is a `struct sockaddr *`
/// holding an AF_UNIX path at offset 2.
fn sockaddr_args() -> Vec<(u16, u8)> {
    let mut out = Vec::new();
    for (name, nr) in syscall_numbers() {
        if name == "bind" || name == "connect" {
            out.push((nr, 1u8));
        }
    }
    if out.is_empty() {
        warn!("no bind/connect in the syscall table; AF_UNIX paths not captured");
    } else {
        info!("sockaddr capture enabled for {} syscalls", out.len());
    }
    out
}

/// Credentials come from the environment when present, so that `testbed/.env` can
/// supply them; the flags still override, and the fallbacks match the old defaults.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn es_user() -> String {
    env_or("ES_USER", "cdr")
}

fn default_pass_file() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let configured = env_or("ES_PASS_FILE", &format!("{home}/.cdr-es-pass"));
    // a shell would expand a leading ~; Rust does not
    match configured.strip_prefix("~/") {
        Some(rest) => format!("{home}/{rest}"),
        None => configured,
    }
}

fn capture_masks() -> Vec<(u16, u8)> {
    const ROOT: &str = "/sys/kernel/tracing/events/syscalls";
    let mut out = Vec::new();
    let names = syscall_numbers();

    if names.is_empty() {
        warn!("syscall table empty; cannot build CAPTURE");
    }
    for (name, nr) in names {
        let Ok(format) = std::fs::read_to_string(format!("{ROOT}/sys_enter_{name}/format")) else { continue };
        let mut mask = 0u8;
        for line in format.lines() {
            let Some(rest) = line.trim_start().strip_prefix("field:") else { continue };
            let Some((ty, tail)) = rest.split_once(";") else { continue };
            if !ty.contains("char") || !ty.contains('*') {
                continue;
            }
            let arg_name = ty.split('*').nth(1).unwrap_or("").trim();
            if !(arg_name.contains("name") || arg_name.contains("path")) { // TODO: consider implications of this
                continue;
            }
            let Some(off) = tail.split("offset:").nth(1) else { continue };
            let Some(off) = off.split(';').next() else { continue };
            let Ok(off) = off.trim().parse::<usize>() else { continue };

            if let Some(idx) = off.checked_sub(16).map(|o| o / 8) {
                if idx < 6 {
                    mask |= 1 << idx;
                }
            }
        }
        if mask != 0 {
            out.push((nr, mask));
        }
    }
    info!("{} syscalls carry user-string arguments", out.len());
    out
}

fn trim_len(bytes: &[u8], cap: usize) -> usize {
    bytes
        .iter()
        .take(cap)
        .position(|b| *b == 0)
        .unwrap_or(bytes.len().min(cap))
}

/// syscall nr -> bitmask of args that are pointer vectors (`char *const *`).
/// Same tracefs metadata as CAPTURE; no syscall is named in this file.
fn capture_argv_masks() -> Vec<(u16, u8)> {
    const ROOT: &str = "/sys/kernel/tracing/events/syscalls";
    let mut out = Vec::new();
    for (name, nr) in syscall_numbers() {
        let Ok(format) = std::fs::read_to_string(format!("{ROOT}/sys_enter_{name}/format")) else {
            continue;
        };
        let mut mask = 0u8;
        for line in format.lines() {
            let Some(rest) = line.trim_start().strip_prefix("field:") else { continue };
            let Some((ty, tail)) = rest.split_once(";") else { continue };
            let is_vec = ty.contains("char") && (ty.contains("*const *") || ty.trim_end().ends_with("**"));
            if !is_vec {
                continue;
            }
            let Some(off) = tail.split("offset:").nth(1) else { continue };
            let Some(off) = off.split(';').next() else { continue };
            let Ok(off) = off.trim().parse::<usize>() else { continue };
            if let Some(idx) = off.checked_sub(16).map(|o| o / 8) {
                if idx < 6 {
                    mask |= 1 << idx;
                }
            }
        }
        if mask != 0 {
            out.push((nr, mask));
        }
    }
    info!("{} syscalls carry pointer-vector arguments", out.len());
    out
}

/// Every process in a container shares its mount namespace, so the container's
/// init pid gives a stable root. Short-lived processes (`bash -c …`) are gone by
/// the time we read the ring, which is why /proc/<tgid>/root alone fails.
fn refresh_roots(
    agents: &[(u64, String)],
    roots: &mut StdHashMap<u64, String>,
    rootfds: &mut StdHashMap<u64, i32>,
) {
    for (ino, dir) in agents {
        let Ok(procs) = std::fs::read_to_string(format!("{dir}/cgroup.procs")) else {
            continue;
        };
        let Some(pid) = procs.lines().next().filter(|l| !l.is_empty()) else {
            continue;
        };
        // Store the MAGIC LINK, not its target: path resolution through
        // /proc/<pid>/root continues inside that process's mount namespace, which
        // is how bind mounts (/shared) are seen at all. Dereferencing to a plain
        // host path would resolve /shared to the overlay's empty mountpoint.
        roots.insert(*ino, format!("/proc/{pid}/root"));
        if !rootfds.contains_key(ino) {
            if let Some(fd) = open_root_fd(pid.trim().parse().unwrap_or(0)) {
                rootfds.insert(*ino, fd);
            }
        }
    }
}

/// Parent directory of a path, for directory-inode attribution.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;
const SYS_OPENAT2: libc::c_long = 437;

fn pack_dev(d: libc::dev_t) -> u64 {
    let d = d as u64;
    let major = ((d >> 8) & 0xfff) | ((d >> 32) & !0xfffu64);
    let minor = (d & 0xff) | ((d >> 12) & !0xffu64);
    (major << 32) | minor
}

// Resolve inside the container's own namespace: RESOLVE_IN_ROOT treats rootfd as
// "/" for the whole walk, including absolute symlink targets and "..". Without it,
// an absolute symlink escapes to the host root and we bind to the wrong inode.
fn key_via_root(rootfd: i32, path: &str) -> Option<(u64, u64)> {
    let rel = path.trim_start_matches('/');
    let c = CString::new(rel).ok()?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            rootfd,
            c.as_ptr(),
            &how as *const OpenHow,
            core::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return None;
    }
    let fd = fd as i32;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    unsafe { libc::close(fd) };
    if rc != 0 {
        return None;
    }
    Some((pack_dev(st.st_dev), st.st_ino))
}

fn key_via_root_str(full: &str) -> Option<(u64, u64)> {
    let c = CString::new(full).ok()?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), 0, libc::STATX_INO, &mut stx) };
    if rc != 0 {
        return None;
    }
    let dev = ((stx.stx_dev_major as u64) << 32) | stx.stx_dev_minor as u64;
    Some((dev, stx.stx_ino))
}

fn open_root_fd(tgid: u32) -> Option<i32> {
    let c = CString::new(format!("/proc/{tgid}/root")).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

fn parent_of(path: &str) -> Option<&str> {
    let t = path.trim_end_matches('/');
    let i = t.rfind('/')?;
    Some(if i == 0 { "/" } else { &t[..i] })
}

fn statx_key(path: &str, tgid: u32, root: Option<&str>, rootfd: Option<i32>) -> Option<(u64, u64)> {
    if path.starts_with('/') {
        if let Some(fd) = rootfd {
            if let Some(k) = key_via_root(fd, path) {
                return Some(k);
            }
        }
        // a cached root can dangle: the pid it was taken from may have exited
        // (cgroup.procs lists whichever pid wrote first). Fall back to the caller.
        if let Some(r) = root {
            if let Some(k) = key_via_root_str(&format!("{r}{path}")) {
                return Some(k);
            }
        }
        if let Some(k) = key_via_root_str(&format!("/proc/{tgid}/root{path}")) {
            return Some(k);
        }
    }
    if path.is_empty() {
        return None;
    }
    let full = if path.starts_with('/') {
        match root {
            Some(r) => format!("{r}{path}"),
            None => format!("/proc/{tgid}/root{path}"),
        }
    } else {
        format!("/proc/{tgid}/cwd/{path}")
    };
    let c = CString::new(full).ok()?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), 0, libc::STATX_INO, &mut stx) };
    if rc != 0 {
        return None;
    }
    let dev = ((stx.stx_dev_major as u64) << 32) | stx.stx_dev_minor as u64;
    Some((dev, stx.stx_ino))
}

fn syscall_name(nr: u16) -> String {
    syscalls::Sysno::new(nr as usize)
        .map(|n| n.name().to_string())
        .unwrap_or_else(|| format!("sys_{nr}"))
}

fn resolve_cached(
    path: &str,
    agent: u64,
    tgid: u32,
    roots: &StdHashMap<u64, String>,
    rootfds: &StdHashMap<u64, i32>,
    cache: &mut StdHashMap<(u64, String), (u64, u64)>,
) -> Option<(u64, u64)> {
    if path.is_empty() {
        return None;
    }
    let key = (agent, path.to_string());
    if let Some(hit) = cache.get(&key) {
        return Some(*hit);
    }
    let resolved = statx_key(path, tgid, roots.get(&agent).map(|s| s.as_str()), rootfds.get(&agent).copied())?;
    cache.insert(key, resolved);
    Some(resolved)
}

fn escape_argv(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            0x1f => s.push_str("\\u001f"),
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\u{:04x}", b)),
        }
    }
    s
}

const MAX_RESOLVE_ATTEMPTS: u8 = 24;

struct Pending {
    ev: Event,
    path: String,
    aux: String,
    attempts: u8,
}

/// Serialize one event. Returns `(line, resolved)`: the caller retries while the
/// target does not exist yet, and prints regardless once attempts run out.
fn fork_offsets() -> Option<(u32, u32)> {
    const P: &str = "/sys/kernel/tracing/events/sched/sched_process_fork/format";
    let text = std::fs::read_to_string(P).ok()?;
    let (mut ptg, mut ctg, mut ppid, mut cpid) = (None, None, None, None);
    for line in text.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix("field:") else { continue };
        let Some((decl, tail)) = rest.split_once(';') else { continue };
        let name = decl.split_whitespace().last().unwrap_or("");
        let Some(off) = tail
            .split("offset:")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            continue;
        };
        match name {
            "parent_tgid" => ptg = Some(off),
            "child_tgid" => ctg = Some(off),
            "parent_pid" => ppid = Some(off),
            "child_pid" => cpid = Some(off),
            _ => {}
        }
    }
    Some((ptg.or(ppid)?, ctg.or(cpid)?))
}

fn ppid_of(tgid: u32, cache: &mut StdHashMap<u32, u32>) -> u32 {
    if let Some(p) = cache.get(&tgid) {
        return *p;
    }
    let Ok(s) = std::fs::read_to_string(format!("/proc/{tgid}/stat")) else {
        return 0;
    };
    let after = match s.rfind(')') {
        Some(i) => &s[i + 1..],
        None => return 0,
    };
    let mut it = after.split_whitespace();
    it.next();
    let ppid = it.next().and_then(|v| v.parse().ok()).unwrap_or(0u32);
    if cache.len() > 100_000 {
        cache.clear();
    }
    cache.insert(tgid, ppid);
    ppid
}

fn render_event(
    ev: &Event,
    path_raw: &str,
    aux_raw: &str,
    roots: &StdHashMap<u64, String>,
    rootfds: &StdHashMap<u64, i32>,
    cache: &mut StdHashMap<(u64, String), (u64, u64)>,
    ppids: &mut StdHashMap<u32, u32>,
) -> (String, bool) {
    let path = escape_argv(path_raw.as_bytes());
    let aux = escape_argv(aux_raw.as_bytes());
    if ev.syscall_nr == 257 || ev.syscall_nr == 2 {
        if ev.arg2 & 0o100 != 0 {
            cache.remove(&(ev.agent_id, path_raw.to_string()));
        }
    }
    let (dev, ino) = resolve_cached(path_raw, ev.agent_id, ev.tgid, roots, rootfds, cache).unwrap_or((0, 0));
    let (adev, aino) = resolve_cached(aux_raw, ev.agent_id, ev.tgid, roots, rootfds, cache).unwrap_or((0, 0));
    let ppid = ppid_of(ev.tgid, ppids);
    let (pdev, pino) = parent_of(path_raw)
        .and_then(|dir| resolve_cached(dir, ev.agent_id, ev.tgid, roots, rootfds, cache))
        .unwrap_or((0, 0));
    let comm = escape_argv(&ev.comm[..trim_len(&ev.comm, MAX_COMM)]);
    let line = format!(
        "{{\"kind\":\"event\",\"ts_ns\":{},\"agent\":{},\"tgid\":{},\"tid\":{},\"nr\":{},\"flags\":{},\"fd\":{},\"dirfd\":{},\"resolved\":{},\"dev\":{},\"ino\":{},\"aux_dev\":{},\"aux_ino\":{},\"ppid\":{},\"pdev\":{},\"pino\":{},\"comm\":\"{comm}\",\"path\":\"{path}\",\"aux\":\"{aux}\",\"args\":[{},{},{},{},{},{}]}}",
        ev.timestamp_ns,
        ev.agent_id,
        ev.tgid,
        ev.tid,
        ev.syscall_nr,
        ev.flags,
        ev.fd,
        ev.dirfd,
        ev.resolved,
        dev,
        ino,
        adev,
        aino,
        ppid,
        pdev,
        pino,
        ev.arg0,
        ev.arg1,
        ev.arg2,
        ev.arg3,
        ev.arg4,
        ev.arg5
    );
    (line, dev != 0)
}

fn payload_line(item: &[u8]) -> Option<String> {
    let hsz = std::mem::size_of::<PayloadHeader>();
    if item.len() < hsz {
        return None;
    }
    let h = unsafe { &*(item.as_ptr() as *const PayloadHeader) };
    if h.kind != PAYLOAD_KIND_ARGV {
        return None;
    }
    let n = (h.len as usize).min(item.len() - hsz);
    let argv = escape_argv(&item[hsz..hsz + n]);
    let idx = (h.pad[0] as u16) | ((h.pad[1] as u16) << 8);
    Some(format!(
        "{{\"kind\":\"argv\",\"ts_ns\":{},\"tgid\":{},\"tid\":{},\"slot\":{},\"i\":{},\"arg\":\"{argv}\"}}",
        h.ts_ns, h.tgid, h.tid, h.pad[2], idx
    ))
}

fn sum_percpu<T: std::borrow::Borrow<aya::maps::MapData>>(
    map: &PerCpuArray<T, u64>,
    idx: u32,
) -> u64 {
    match map.get(&idx, 0) {
        Ok(values) => values.iter().sum(),
        Err(_) => 0,
    }
}

fn register_children<T: std::borrow::BorrowMut<aya::maps::MapData>>(
    map: &mut aya::maps::HashMap<T, u64, u32>,
    root: &str,
    agents: &mut Vec<(u64, String)>,
    declared: &[String],
) -> anyhow::Result<()> {
    let mut add = |path: &std::path::Path,
                   map: &mut aya::maps::HashMap<T, u64, u32>,
                   agents: &mut Vec<(u64, String)>|
     -> anyhow::Result<()> {
        let Ok(meta) = std::fs::metadata(path) else { return Ok(()) };
        let ino = meta.ino();
        if agents.iter().any(|(i, _)| *i == ino) {
            return Ok(());
        }
        map.insert(ino, agents.len() as u32, 0)?;
        agents.push((ino, path.display().to_string()));
        Ok(())
    };

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                add(&path, map, agents)?;
            }
        }
    }

    for path in declared {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            add(p, map, agents)?;
        } else {
            warn!("declared agent cgroup missing: {path}");
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("replay") => return replay(),
        Some("baseline") => return baseline::main(),
        Some("desync") => return reconcile::reconcile(),
        Some("reasoning") => return reasoning::ingest(),
        Some("score") => return score::score(),
        Some("init") => {
            let a: Vec<String> = std::env::args().collect();
            let opt = |n: &str, d: &str| {
                a.iter().position(|x| x == n).and_then(|i| a.get(i + 1)).cloned().unwrap_or_else(|| d.to_string())
            };
            let pass_file = opt("--password-file", &default_pass_file());
            let pass = std::fs::read_to_string(&pass_file).unwrap_or_default();
            if pass.trim().is_empty() {
                eprintln!("[WARN  ebpf_agent] no ES password read from {pass_file}");
            }
            return es::init(&opt("--es", "http://127.0.0.1:9200"), &es_user(), pass.trim());
        }
        Some("run") | None => {}
        Some(other) => anyhow::bail!("unknown command {other}: expected run|replay|baseline"),
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?
        .block_on(sensor_main())
}

fn replay() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let opt = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let input = args.get(2).cloned().unwrap_or_else(|| "-".into());
    let window_ms: u64 = opt("--window-ms", "30000").parse().unwrap_or(30_000);
    let edges_path = opt("--edges", "edges.jsonl");
    let index = opt("--index", "cdr-edges");
    let es_url = args.iter().position(|a| a == "--es").and_then(|i| args.get(i + 1)).cloned();
    let pass_file = opt("--password-file", &default_pass_file());
    let dead_letter = opt("--dead-letter", "es-dead.ndjson");

    let text = if input == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(&input)?
    };

    let mut correlator = correlate::Correlator::new(window_ms);
    let mut edge_spool = BufWriter::new(File::create(&edges_path)?);
    let (tx, shipper) = match es_url {
        Some(url) => {
            let pass = std::fs::read_to_string(&pass_file).unwrap_or_default();
            if pass.trim().is_empty() {
                eprintln!("[WARN  ebpf_agent] no ES password read from {pass_file}");
            }
            let sink = es::Sink::new(&url, &es_user(), pass.trim(), &index, &dead_letter);
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(10_000);
            (Some(tx), Some(es::spawn_shipper(sink, rx)))
        }
        None => (None, None),
    };
    let mut queue_drops = 0u64;
    for line in text.lines() {
        for out in correlator.ingest(line) {
            let _ = writeln!(edge_spool, "{out}");
            if let Some(tx) = &tx {
                if !es::offer(tx, out.clone()) {
                    queue_drops += 1;
                }
            }
        }
    }
    let _ = edge_spool.flush();
    drop(tx);
    let stats = shipper.map(|h| h.join().ok()).flatten();
    if let Some(s) = &stats {
        eprintln!("replay: shipped={} failed={} queue_dropped={queue_drops}", s.shipped, s.failed);
    }
    eprintln!("replay: {} edges from {input}", correlator.edges);
    Ok(())
}

async fn sensor_main() -> anyhow::Result<()> {
    env_logger::init();

    // Rust ignores SIGPIPE, so a closed downstream (edges exiting on Ctrl-C)
    // turns the next println! into a panic. Restore the Unix default: die quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-agent"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            log::warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // SAFETY: the logger owns its file descriptor, which stays open and unchanged
            // while the AsyncFd owns it. We only flush the logger, never replace it.
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            }?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut TracePoint = ebpf.program_mut("sys_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    if let Some((parent_off, child_off)) = fork_offsets() {
        if let Some(prog) = ebpf.program_mut("sched_fork") {
            let fork: &mut TracePoint = prog.try_into()?;
            fork.load()?;
            fork.attach("sched", "sched_process_fork")?;
            let mut cfg = HashMap::try_from(ebpf.take_map("CONFIG").unwrap())?;
            cfg.insert(1u32, parent_off, 0)?;
            cfg.insert(2u32, child_off, 0)?;
            eprintln!("[INFO  ebpf_agent] fork tracepoint on, parent_off={parent_off} child_off={child_off}");
        }
    } else {
        warn!("sched_process_fork format not found: ppid falls back to /proc");
    }

    let target_path = if Path::new(TESTBED_SLICE).exists() {
        TESTBED_SLICE
    } else {
        println!("TESTBED_SLICE not found - considering as production");
        "/sys/fs/cgroup/user.slice"
    };


    let mut target_groups = HashMap::try_from(ebpf.take_map("TARGET_CGROUPS").unwrap())?;
    let declared: Vec<String> = std::env::args()
        .collect::<Vec<String>>()
        .iter()
        .position(|a| a == "--agent-cgroups")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|f| std::fs::read_to_string(f).ok())
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut agents: Vec<(u64, String)> = Vec::new();
    register_children(&mut target_groups, target_path, &mut agents, &declared)?;
    if agents.len() < 2 {
        warn!("{} cgroups under {target_path}: agents will share an identity", agents.len())
    }

    let mut capture = HashMap::try_from(ebpf.take_map("CAPTURE").unwrap())?;

    let masks = capture_masks();
    if masks.is_empty() {
        anyhow::bail!("capture is empty; unreadable format");
    }
    for (nr, mask) in masks {
        capture.insert(nr, mask, 0)?;
    }

    // `bind` and `connect` name their object inside a sockaddr, not a path string
    let mut capture_off = aya::maps::HashMap::<_, u16, u8>::try_from(ebpf.take_map("CAPTURE_OFF").unwrap())?;
    for (nr, idx) in sockaddr_args() {
        let have = capture.get(&nr, 0).unwrap_or(0);
        capture.insert(nr, have | (1 << idx), 0)?;
        capture_off.insert(nr, 2, 0)?;
    }

    let mut capture_argv = HashMap::try_from(ebpf.take_map("CAPTURE_ARGV").unwrap())?;
    for (nr, mask) in capture_argv_masks() {
        capture_argv.insert(nr, mask, 0)?;
    }

    let mut ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut payloads = RingBuf::try_from(ebpf.take_map("PAYLOADS").unwrap())?;
    let drops = PerCpuArray::<_, u64>::try_from(ebpf.take_map("DROPS").unwrap())?;
    let oos = PerCpuArray::<_, u64>::try_from(ebpf.take_map("OOS").unwrap())?;
    let pdrops = PerCpuArray::<_, u64>::try_from(ebpf.take_map("PDROPS").unwrap())?;
    let nr_hist = PerCpuArray::<_, u64>::try_from(ebpf.take_map("NR_HIST").unwrap())?;

    let mut ino_cache: StdHashMap<(u64, String), (u64, u64)> = StdHashMap::new();
    let mut ppids: StdHashMap<u32, u32> = StdHashMap::new();
    let mut roots: StdHashMap<u64, String> = StdHashMap::new();
    let mut rootfds: StdHashMap<u64, i32> = StdHashMap::new();
    let mut pending: std::collections::VecDeque<Pending> = std::collections::VecDeque::new();
    refresh_roots(&agents, &mut roots, &mut rootfds);
    eprintln!("[INFO  ebpf_agent] resolved {} container namespace roots", roots.len());
    for (ino, dir) in &agents {
        // join table: the corpus identifies agents by inode, humans by container
        eprintln!("[INFO  ebpf_agent] agent ino={ino} cgroup={dir}");
    }
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))?;

    // build provenance: every episode's log names the binary that produced it
    let built = std::env::current_exe()
        .and_then(std::fs::metadata)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    eprintln!("[INFO  ebpf_agent] binary_built_unix={built}");

    let args: Vec<String> = std::env::args().collect();
    let opt = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let spool_path = opt("--spool", "events.jsonl");
    let edges_path = opt("--edges", "edges.jsonl");
    let window_ms: u64 = opt("--window-ms", "30000").parse().unwrap_or(30_000);
    let es_url = args.iter().position(|a| a == "--es").and_then(|i| args.get(i + 1)).cloned();
    let index = opt("--index", "cdr-edges");
    let pass_file = opt("--password-file", &default_pass_file());
    let dead_letter = opt("--dead-letter", "es-dead.ndjson");

    let mut spool = BufWriter::new(File::create(&spool_path)?);
    let mut edge_spool = BufWriter::new(File::create(&edges_path)?);
    let mut correlator = correlate::Correlator::new(window_ms);

    let (tx, shipper) = match es_url {
        Some(url) => {
            let pass = std::fs::read_to_string(&pass_file).unwrap_or_default();
            if pass.trim().is_empty() {
                eprintln!("[WARN  ebpf_agent] no ES password read from {pass_file}");
            }
            let sink = es::Sink::new(&url, &es_user(), pass.trim(), &index, &dead_letter);
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(10_000);
            (Some(tx), Some(es::spawn_shipper(sink, rx)))
        }
        None => (None, None),
    };
    let mut queue_drops: u64 = 0;

    eprintln!("[INFO  ebpf_agent] streaming -> {spool_path} / {edges_path}; Ctrl-C to stop");

    while running.load(Ordering::SeqCst) {
        // Events whose target did not exist at sys_enter are retried: creation
        // events always lose that race, the tracepoint fires before the file exists.
        let mut retry = 0;
        while retry < pending.len() {
            let p = pending.pop_front().unwrap();
            if p.ev.syscall_nr == 0xFFFE {
                let line = format!(
                    "{{\"kind\":\"fork\",\"ts_ns\":{},\"ppid\":{},\"tgid\":{},\"agent\":{}}}",
                    p.ev.timestamp_ns, p.ev.arg0, p.ev.arg1, p.ev.agent_id
                );
                let _ = writeln!(spool, "{line}");
                if let Some(tx) = &tx {
                    if !es::offer(tx, line) {
                        queue_drops += 1;
                    }
                }
                continue;
            }
            let (line, resolved) = render_event(&p.ev, &p.path, &p.aux, &roots, &rootfds, &mut ino_cache, &mut ppids);
            if resolved || p.attempts >= MAX_RESOLVE_ATTEMPTS || p.path.is_empty() {
                let _ = writeln!(spool, "{line}");
                for out in correlator.ingest(&line) {
                    let _ = writeln!(edge_spool, "{out}");
                    if let Some(tx) = &tx {
                        if !es::offer(tx, out.clone()) {
                            queue_drops += 1;
                        }
                    }
                }
            } else {
                pending.push_back(Pending { attempts: p.attempts + 1, ..p });
            }
            retry += 1;
        }

        while let Some(item) = payloads.next() {
            if let Some(line) = payload_line(&item) {
                let _ = writeln!(spool, "{line}");
                if let Some(tx) = &tx {
                    if !es::offer(tx, line) {
                        queue_drops += 1;
                    }
                }
            }
        }
        if let Some(item) = ring_buf.next() {
            if item.len() >= std::mem::size_of::<Event>() {
                let event = unsafe { &*(item.as_ptr() as *const Event) };

                let path_raw =
                    String::from_utf8_lossy(&event.path[..trim_len(&event.path, MAX_PATH)]).into_owned();
                let aux_raw =
                    String::from_utf8_lossy(&event.aux[..trim_len(&event.aux, MAX_AUX)]).into_owned();
                pending.push_back(Pending {
                    ev: *event,
                    path: path_raw,
                    aux: aux_raw,
                    attempts: 0,
                });
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    let _ = spool.flush();
    let _ = edge_spool.flush();
    drop(tx);
    let sink_stats = shipper.map(|h| h.join().ok()).flatten();
    if let Some(s) = &sink_stats {
        eprintln!(
            "es-sink: shipped={} failed={} queue_dropped={queue_drops}",
            s.shipped, s.failed
        );
    }

    let drops_total = sum_percpu(&drops, 0);
    let payload_drops = sum_percpu(&pdrops, 0);
    let oos_total = sum_percpu(&oos, 0);
    let syscalls: u64 = (0..512u32).map(|nr| sum_percpu(&nr_hist, nr)).sum();
    eprintln!(
        "Exiting... events_ok, drops={drops_total}, payload_drops={payload_drops}, oos={oos_total}, syscalls={syscalls}"
    );
    // which syscalls dominate the unclassified remainder: a coverage claim without
    // this list is just a percentage
    let mut hist: Vec<(u32, u64)> = (0..512u32)
        .map(|nr| (nr, sum_percpu(&nr_hist, nr)))
        .filter(|(_, c)| *c > 0)
        .collect();
    hist.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    let top: Vec<String> = hist
        .iter()
        .take(10)
        .map(|(nr, c)| format!("{}({}:{})", syscall_name(*nr as u16), nr, c))
        .collect();
    eprintln!("[INFO  ebpf_agent] nr_hist_top10={}", top.join(" "));

    Ok(())
}
