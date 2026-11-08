#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, helpers::generated::bpf_get_current_cgroup_id};
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes, bpf_get_current_ancestor_cgroup_id};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerCpuArray, PerCpuHashMap, RingBuf};
use ebpf_agent_common::{Event, PayloadHeader, EVENT_SCHEMA_VERSION, MAX_AUX, MAX_COMM, MAX_ARGV_ELEM, MAX_PATH, PAYLOAD_KIND_ARGV, RESOLVED_AUX, RESOLVED_PATH};

#[map]
static TARGET_CGROUPS: HashMap<u64, u32> = HashMap::with_max_entries(128, 0);

#[map]
static AGENT_CACHE: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

// syscall nr -> bitmask of arg indices to read as strings
#[map]
static CAPTURE: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(64, 0);

// Variable-length side channel: argv vectors and oversized paths, correlated to
// an Event by (ts_ns, tgid). Reserved at MAX_PAYLOAD; the header carries the
// real length, so trailing bytes are unspecified.
#[map]
static PAYLOADS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// syscall nr -> bitmask of arg indices that are `char *const *` vectors
#[map]
static CAPTURE_ARGV: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

// syscall nr -> byte offset to skip before reading the path string, used for
// `struct sockaddr *` arguments where the name lives at sun_path (offset 2).
#[map]
static CAPTURE_OFF: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

const NR_FORK: u16 = 0xFFFE;

// payload-ring losses, counted separately: argv can be lost while events survive
#[map]
static PDROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static OOS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NR_HIST: PerCpuArray<u64> = PerCpuArray::with_max_entries(512, 0);

#[inline(always)]
fn arg(args: [u64; 6], idx: u32) -> u64 {
    match idx {
        0 => args[0],
        1 => args[1],
        2 => args[2],
        3 => args[3],
        4 => args[4],
        _ => args[5],
    }
}

#[inline(always)]
fn bump(map: &PerCpuArray<u64>, idx: u32) {
    if let Some(p) = map.get_ptr_mut(idx) {
        unsafe { *p += 1 }
    }
}

#[inline(always)]
unsafe fn resolve_agent(leaf: u64) -> Option<(u64, u32)> {
    if let Some(ordinal) = unsafe { TARGET_CGROUPS.get(&leaf) } {
        return Some((leaf, *ordinal));
    }

    if let Some(cached) = unsafe { AGENT_CACHE.get(&leaf) } {
        if *cached == 0 {
            return None;
        }
        let id = *cached;
        return unsafe { TARGET_CGROUPS.get(&id) }.map(|o| (id, *o));
    }

    let mut level: i32 = 1;

    while level <= 6 {
        let id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if id != 0 {
            if let Some(ordinal) = unsafe { TARGET_CGROUPS.get(&id) } {
                return Some((id, *ordinal));
            }
        }
        level += 1;
    }
    let _ = AGENT_CACHE.insert(&leaf, 0, 0);
    None
}

#[inline(always)]
unsafe fn read_str(ev: *mut Event, is_path: bool, ptr: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    let (dst, cap) = if is_path {
        (unsafe { (*ev).path.as_mut_ptr() }, MAX_PATH )
    } else {
        (unsafe { (*ev).aux.as_mut_ptr() }, MAX_AUX)
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(dst, cap) };
    unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, buf) }.is_ok()
}

#[tracepoint]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    let parent_off = (unsafe { CONFIG.get(&1) }).copied().unwrap_or(0) as usize;
    let child_off = (unsafe { CONFIG.get(&2) }).copied().unwrap_or(0) as usize;
    if parent_off == 0 || child_off == 0 {
        return 0;
    }
    let Ok(parent) = (unsafe { ctx.read_at::<i32>(parent_off) }) else { return 0 };
    let Ok(child) = (unsafe { ctx.read_at::<i32>(child_off) }) else { return 0 };
    if parent <= 0 || child <= 0 {
        return 0;
    }
    let leaf = unsafe { bpf_get_current_cgroup_id() };
    let Some((agent_id, _ordinal)) = (unsafe { resolve_agent(leaf) }) else { return 0 };
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else { return 0 };
    let ev = entry.as_mut_ptr();
    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        (*ev).timestamp_ns = bpf_ktime_get_ns();
        (*ev).cgroup_id = leaf;
        (*ev).agent_id = agent_id;
        (*ev).ret = 0;
        (*ev).arg0 = parent as u64;
        (*ev).arg1 = child as u64;
        (*ev).arg2 = 0;
        (*ev).arg3 = 0;
        (*ev).arg4 = 0;
        (*ev).arg5 = 0;
        (*ev).dev = 0;
        (*ev).ino = 0;
        (*ev).tgid = (pid_tgid >> 32) as u32;
        (*ev).tid = pid_tgid as u32;
        (*ev).kind = 0;
        (*ev).flags = 0;
        (*ev).fd = -1;
        (*ev).dirfd = -1;
        (*ev).schema = EVENT_SCHEMA_VERSION;
        (*ev).syscall_nr = NR_FORK;
        (*ev).resolved = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or([0u8; MAX_COMM]);
        (*ev).path = [0u8; MAX_PATH];
        (*ev).aux = [0u8; MAX_AUX];
        (*ev).pad = [0u8; 11];
    }
    entry.submit(0);
    0
}

#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    // info!(&ctx, "tracepoint sys_enter called");
    let _ = try_sys_enter(ctx);
    0
}

fn try_sys_enter(ctx: TracePointContext) -> Result<(), u32> {
    // cgroups are made of leafs and ancestors
    // hence we check at the bottom level, and then raise at least 6^

    let leaf_cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let Some((agent_id, agent_ordinal)) = (unsafe { resolve_agent(leaf_cgroup_id) }) else {
        bump(&OOS, 0);
        return Ok(());
    };

    let syscall_nr: i64 = unsafe { ctx.read_at(8).map_err(|_| 1u32)? };

    let hist_slot = if syscall_nr >= 0 && syscall_nr < 512i64 { syscall_nr as u32 } else { 511 };
    bump(&NR_HIST, hist_slot);

    let Ok(nr_key) = u16::try_from(syscall_nr) else { return Ok(()) };

    let Some(mask) = (unsafe { CAPTURE.get(&nr_key) }).copied() else { return Ok(()) };

    let args: [u64; 6] = [
        unsafe { ctx.read_at(16).map_err(|_| 2u32)? },
        unsafe { ctx.read_at(24).map_err(|_| 3u32)? },
        unsafe { ctx.read_at(32).map_err(|_| 4u32)? },
        unsafe { ctx.read_at(40).map_err(|_| 5u32)? },
        unsafe { ctx.read_at(48).map_err(|_| 6u32)? },
        unsafe { ctx.read_at(56).map_err(|_| 7u32)? },
    ];

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(&DROPS, agent_ordinal);
        return Ok(());
    };

    let ev = entry.as_mut_ptr();
    let pid_tgid = bpf_get_current_pid_tgid();

    unsafe {
        (*ev).timestamp_ns = bpf_ktime_get_ns();
        (*ev).cgroup_id = leaf_cgroup_id;
        (*ev).agent_id = agent_id;
        (*ev).ret = 0;
        (*ev).arg0 = args[0];
        (*ev).arg1 = args[1];
        (*ev).arg2 = args[2];
        (*ev).arg3 = args[3];
        (*ev).arg4 = args[4];
        (*ev).arg5 = args[5];
        (*ev).dev = 0;
        (*ev).ino = 0;
        (*ev).tgid = (pid_tgid >> 32) as u32;
        (*ev).tid = pid_tgid as u32;
        (*ev).kind = 0;
        (*ev).flags = 0;
        (*ev).fd = -1;
        (*ev).dirfd = -1;
        (*ev).schema = EVENT_SCHEMA_VERSION;
        (*ev).syscall_nr = nr_key;
        (*ev).resolved = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or([0u8; MAX_COMM]);
        (*ev).path = [0u8; MAX_PATH];
        (*ev).aux = [0u8; MAX_AUX];
        (*ev).pad = [0u8; 11];
    }

    let mut slot = 0u32;
    let mut i = 0u32;

    // fill strings
    while i < 6 {
        if mask & (1 << i) != 0 && slot < 2 {
            let is_path = slot == 0;
            let off = if is_path {
                unsafe { CAPTURE_OFF.get(&nr_key) }.copied().unwrap_or(0)
            } else {
                0
            };
            let mut ptr = arg(args, i);
            let mut got = false;
            if off == 0 {
                got = unsafe { read_str(ev, is_path, ptr) };
            } else if ptr != 0 {
                // `struct sockaddr *`: only AF_UNIX carries a filesystem name,
                // and it sits after the 2-byte family field.
                let fam: u16 = unsafe { bpf_probe_read_user(ptr as *const u16) }.unwrap_or(0);
                if fam == 1 {
                    ptr = ptr.wrapping_add(off as u64);
                    got = unsafe { read_str(ev, is_path, ptr) };
                }
            }
            if got {
                unsafe { (*ev).resolved |= if is_path { RESOLVED_PATH } else { RESOLVED_AUX } };
            }
            slot += 1;
        }
        i += 1;
    }

    // argv vectors travel on the payload side channel, untruncated
    if let Some(argv_mask) = (unsafe { CAPTURE_ARGV.get(&nr_key) }).copied() {
        let ts = unsafe { (*ev).timestamp_ns };
        let mut j = 0u32;
        while j < 6 {
            if argv_mask & (1 << j) != 0 {
                unsafe { emit_argv(ts, (*ev).tgid, (*ev).tid, j as u8, arg(args, j)) };
            }
            j += 1;
        }
    }

    entry.submit(0);
    Ok(())
}

/// Walk a `char *const *` vector, emitting one payload record per element.
///
/// One record per element keeps every write at a CONSTANT offset with a
/// CONSTANT length, which is what the verifier can prove. A prior version
/// concatenated elements at a runtime offset and was rejected:
/// `invalid access to memory, mem_size=2080 off=2078 size=2025`.
#[inline(always)]
unsafe fn emit_argv(ts_ns: u64, tgid: u32, tid: u32, slot: u8, vec: u64) {
    if vec == 0 {
        return;
    }
    const MAX_ARG_ELEMS: u64 = 24;
    let mut i: u64 = 0;
    while i < MAX_ARG_ELEMS {
        let Ok(p) = (unsafe { bpf_probe_read_user::<u64>((vec + i * 8) as *const u64) }) else {
            break;
        };
        if p == 0 {
            break;
        }
        unsafe { emit_arg(ts_ns, tgid, tid, slot, i as u16, p) };
        i += 1;
    }
}

/// One argv element: header + fixed MAX_ARG bytes.
#[inline(always)]
unsafe fn emit_arg(ts_ns: u64, tgid: u32, tid: u32, slot: u8, idx: u16, ptr: u64) {
    const HDR: usize = core::mem::size_of::<PayloadHeader>();
    let Some(mut entry) = PAYLOADS.reserve_bytes(HDR + MAX_ARGV_ELEM, 0) else {
        if let Some(p) = PDROPS.get_ptr_mut(0) {
            unsafe { *p += 1 }
        }
        return;
    };

    let base = entry.as_mut_ptr();
    let hdr = base as *mut PayloadHeader;
    unsafe {
        core::ptr::write_bytes(base, 0, HDR);
        (*hdr).ts_ns = ts_ns;
        (*hdr).tgid = tgid;
        (*hdr).tid = tid;
        (*hdr).kind = PAYLOAD_KIND_ARGV;
        (*hdr).schema = EVENT_SCHEMA_VERSION;
        (*hdr).len = 0;
        (*hdr).pad[0] = idx as u8;
        (*hdr).pad[1] = (idx >> 8) as u8;
        (*hdr).pad[2] = slot; // which register the vector came from
    }

    // constant offset, constant length: verifier-friendly
    let buf = unsafe { core::slice::from_raw_parts_mut(base.add(HDR), MAX_ARGV_ELEM) };
    match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, buf) } {
        Ok(s) => unsafe { (*hdr).len = s.len() as u16 },
        Err(_) => {
            entry.discard(0);
            return;
        }
    }
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
