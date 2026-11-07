#![no_std]

pub const EVENT_SCHEMA_VERSION: u16 = 1;

pub const MAX_PATH: usize = 64;
pub const MAX_AUX: usize = 32;
pub const MAX_COMM: usize = 16;

pub const RESOLVED_INODE: u8 = 1 << 0; // dev/ino valid
pub const RESOLVED_PATH: u8 = 1 << 1; // path valid, non empty
pub const RESOLVED_AUX: u8 = 1 << 2; // aux present
pub const SPLIT_PRIMARY: u8 = 1 << 3; // dev/ino describes path
pub const SPLIT_SECONDARY: u8 = 1 << 4; // dev/ino describes aux

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Unknown = 0, Open = 1, Read = 2, Write = 3, Truncate = 4, Mmap = 5,
    Xattr = 6, Times = 7, Mode = 8, Owner = 9, Create = 10, Unlink = 11,
    Rename = 12, Link = 13, Getdents = 14, Stat = 15, Lock = 16,
    IpcCreate = 17, IpcSend = 18, IpcRecv = 19, Signal = 20,
    Connect = 21, Sendto = 22, Recvfrom = 23, WatchAdd = 24,
    Fallocate = 25, Futex = 26, Yield = 27, Sleep = 28,
    Clock = 29, Exec = 30, Clone = 31, UringEnter = 32, UringRegister = 33
}


// dirfd, path, aux, flags, and fd are kind dependent
// enriched from syscall kind
// argX are raw registers
// comm can take all 16 bytes with no null terminator TBE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub agent_id: u64,
    pub ret: i64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,

    // assurance for integrity (device, inode) for paths
    pub dev: u64,
    pub ino: u64,

    pub tgid: u32,
    pub tid: u32,

    pub kind: u32,
    pub flags: u32,
    pub fd: i32,
    pub dirfd: i32,

    pub schema: u16,
    pub syscall_nr: u16,
    pub resolved: u8,
    pub comm: [u8; MAX_COMM],
    pub path: [u8; MAX_PATH],
    pub aux: [u8; MAX_AUX],

    pub pad: [u8; 11] // rfu
}

const _: () = assert!(core::mem::size_of::<Event>() == 248);
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Event, arg5) == 72);
    assert!(offset_of!(Event, dev) == 80);
    assert!(offset_of!(Event, kind) == 104);
    assert!(offset_of!(Event, resolved) == 124);
    assert!(offset_of!(Event, path) == 141);
    assert!(offset_of!(Event, aux) == 205);
};

// Payload side-channel

pub const MAX_PAYLOAD: usize = 2048;

/// One argv element per payload record; a single argument longer than this
/// truncates, the command line does not.
pub const MAX_ARGV_ELEM: usize = 256;

pub const PAYLOAD_KIND_ARGV: u16 = 1;
pub const PAYLOAD_KIND_PATH: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PayloadHeader {
    pub ts_ns: u64, // matches Event::timestamp_ns
    pub tgid: u32,
    pub tid: u32,
    pub len: u16,
    pub kind: u16,
    pub schema: u16,
    pub pad: [u8; 10],
}

const _: () = assert!(core::mem::size_of::<PayloadHeader>() == 32);