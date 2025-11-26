use ctor::ctor;
use core::ffi::c_char;
use core::ffi::c_int;
use std::sync::{Mutex, OnceLock};
use std::ffi::CString;
use core::slice;
use std::thread;
use std::mem;
use std::ptr;

// Provide a few C-compatible symbols the Rust crate used to get from the
// proxychains-C helper sources so the crate can compile & run without linking
// the C static library. These implementations are intentionally minimal and
// conservative — they aim to provide correct symbols and safe defaults so the
// rest of the crate can run standalone. More complete replacements can be
// implemented incrementally if you want to preserve full runtime parity.

// req_pipefd / resp_pipefd are used by some parts of the runtime to protect
// internal pipe FDs and for the old "at" remote-dns mode. We create simple
// pipes at library init time so the FDs are valid (>=0) and can be used in
// comparisons. Implementation mirrors the behaviour used elsewhere: two ints.
#[no_mangle]
pub static mut req_pipefd: [c_int; 2] = [-1, -1];

#[no_mangle]
pub static mut resp_pipefd: [c_int; 2] = [-1, -1];

// Create pipes on library load so the FD values exist and are not -1.
// Use the ctor crate so this runs when the library is loaded.
#[ctor]
fn init_compat_pipes() {
    unsafe {
        // libc::pipe expects *mut c_int
        let mut r: [c_int; 2] = [-1, -1];
        if libc::pipe(r.as_mut_ptr() as *mut libc::c_int) == 0 {
            // Make them non-blocking to be safer with event loops
            let flags0 = libc::fcntl(r[0], libc::F_GETFL);
            if flags0 != -1 {
                libc::fcntl(r[0], libc::F_SETFL, flags0 | libc::O_NONBLOCK);
            }
            let flags1 = libc::fcntl(r[1], libc::F_GETFL);
            if flags1 != -1 {
                libc::fcntl(r[1], libc::F_SETFL, flags1 | libc::O_NONBLOCK);
            }
            req_pipefd = r;
        } else {
            // fallback: leave -1s so comparisons still work
        }

        let mut s: [c_int; 2] = [-1, -1];
        if libc::pipe(s.as_mut_ptr() as *mut libc::c_int) == 0 {
            let flags0 = libc::fcntl(s[0], libc::F_GETFL);
            if flags0 != -1 {
                libc::fcntl(s[0], libc::F_SETFL, flags0 | libc::O_NONBLOCK);
            }
            let flags1 = libc::fcntl(s[1], libc::F_GETFL);
            if flags1 != -1 {
                libc::fcntl(s[1], libc::F_SETFL, flags1 | libc::O_NONBLOCK);
            }
            resp_pipefd = s;
        }
    }
}

// Provide a tiny version string function used by libproxychains printf logs.
// Match the C name so code that refers to proxychains_get_version keeps working.
#[no_mangle]
pub extern "C" fn proxychains_get_version() -> *const c_char {
    // Keep a static, null-terminated C string. Match the C project's
    // VERSION so runtime logs show the same version (proxychains-C uses
    // the top-level VERSION file which currently contains "5.0.0").
    static VER: &[u8] = b"5.0.0\0";
    VER.as_ptr() as *const c_char
}


// Port of proxychains-C's dalias_hash() so we don't need hash.c when
// building the Rust-only crate. This mirrors the C implementation: iterate
// bytes, compute h = 16*h + byte, then apply h ^= (h >> 24) & 0xf0. Return
// the lower 28 bits.
#[no_mangle]
pub extern "C" fn dalias_hash(s0: *mut c_char) -> u32 {
    if s0.is_null() {
        return 0u32;
    }

    unsafe {
        let mut p = s0 as *const u8;
        let mut h: u32 = 0;
        // iterate until null byte
        loop {
            let cur = *p;
            if cur == 0 { break }
            // match C semantics (wrap on overflow)
            h = h.wrapping_mul(16).wrapping_add(cur as u32);
            h ^= (h >> 24) & 0xf0;
            p = p.add(1);
        }
        h & 0x0fff_ffffu32
    }
}

// Minimal "at" remote-dns interface used by rdns.rs when DNSLF_RDNS_THREAD
// mode is selected. We implement no-op / failure return values so the runtime
// does not rely on the C allocator thread implementation; callers should
// interpret failures accordingly.
use crate::rdns::ip_type4;

// Reimplementation of the allocator-thread's in-process mapping table used by
// the legacy 'at_*' API. Instead of mmap + a helper thread, we provide a
// mutex-protected vector which is safe and easier to maintain in Rust.

const MSG_LEN_MAX: usize = 256;

#[derive(Clone)]
struct StringEntry {
    hash: u32,
    string: CString,
}

static INTERNAL_IPS: OnceLock<Mutex<Vec<StringEntry>>> = OnceLock::new();
static ALLOC_THREAD: OnceLock<Mutex<Option<std::thread::JoinHandle<()>>>> = OnceLock::new();
// serialize paired request/response operations from callers (C used a mutex)
static REQ_RESP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn IPT4_INVALID() -> ip_type4 {
    ip_type4 { as_int: -(1 as libc::c_int) as u32 }
}

fn make_internal_ip(index: u32) -> ip_type4 {
    unsafe {
        let mut idx = index + 1;
        if idx > 0xFFFFFFu32 { return IPT4_INVALID(); }
        let subnet = crate::libproxychains::remote_dns_subnet as u32 & 0xFF;
        let oct0 = (subnet & 0xff) as u8;
        let oct1 = ((idx & 0xFF0000) >> 16) as u8;
        let oct2 = ((idx & 0xFF00) >> 8) as u8;
        let oct3 = (idx & 0xFF) as u8;
        let mut ret = ip_type4 { as_int: 0 };
        ret.octet = [oct0, oct1, oct2, oct3];
        ret
    }
}

fn index_from_internal_ip(internalip: ip_type4) -> usize {
    unsafe {
        let tmp = internalip;
        let mut ret = tmp.octet[3] as u32 + ((tmp.octet[2] as u32) << 8) + ((tmp.octet[1] as u32) << 16);
        if ret == 0 { return 0usize; }
        ret -= 1;
        ret as usize
    }
}

// helpers for raw IO
unsafe fn read_exact_fd(fd: i32, mut buf: *mut u8, mut bytes: usize) -> bool {
    while bytes > 0 {
        let ret = libc::read(fd, buf as *mut libc::c_void, bytes);
        if ret <= 0 {
            if ret == -1 && *libc::__errno_location() == libc::EINTR { continue; }
            return false;
        }
        buf = buf.add(ret as usize);
        bytes -= ret as usize;
    }
    true
}

unsafe fn write_exact_fd(fd: i32, mut buf: *const u8, mut bytes: usize) -> bool {
    while bytes > 0 {
        let ret = libc::write(fd, buf as *const libc::c_void, bytes);
        if ret <= 0 {
            if ret == -1 && *libc::__errno_location() == libc::EINTR { continue; }
            return false;
        }
        buf = buf.add(ret as usize);
        bytes -= ret as usize;
    }
    true
}

#[no_mangle]
pub extern "C" fn at_init() {
    // Initialize the allocator mapping table on first use. The original C
    // implementation created shared memory and a helper thread. Our Rust
    // replacement uses a Mutex-protected vector that provides the same
    // observable behaviour for the at_* accessors.
    INTERNAL_IPS.get_or_init(|| Mutex::new(Vec::with_capacity(64)));
    // ensure request/response serialization mutex exists
    REQ_RESP_LOCK.get_or_init(|| Mutex::new(()));

    // spawn allocator thread if it's not running already
    let guard = ALLOC_THREAD.get_or_init(|| Mutex::new(None));
    let mut handle_slot = guard.lock().unwrap();
    if handle_slot.is_some() { return; }

    // spawn thread that listens on req_pipefd[0] and replies on resp_pipefd[1]
    let th = thread::spawn(|| {
        unsafe {
            let req_read = req_pipefd[0];
            let resp_write = resp_pipefd[1];

            loop {
                // read header
                let mut hdr: crate::rdns::at_msghdr = mem::zeroed();
                let hdr_ptr = &mut hdr as *mut _ as *mut u8;
                if !read_exact_fd(req_read, hdr_ptr, mem::size_of::<crate::rdns::at_msghdr>()) {
                    continue;
                }
                let datalen = hdr.datalen as usize;

                // allocate message container
                let mut msg: crate::rdns::at_msg = mem::zeroed();
                msg.h = hdr;
                if datalen > 0 {
                    let mptr = &mut msg.m as *mut _ as *mut u8;
                    if !read_exact_fd(req_read, mptr, datalen) {
                        continue;
                    }
                }

                match hdr.msgtype as i32 {
                    x if x == crate::rdns::ATM_GETIP as i32 => {
                        // compute ip (may allocate)
                        let host_ptr = msg.m.host.as_mut_ptr();
                        let s_len = libc::strlen(host_ptr as *const i8) as usize;
                        let s_slice = std::slice::from_raw_parts(host_ptr as *const u8, s_len);
                        let mut buf = Vec::with_capacity(s_slice.len()+1);
                        buf.extend_from_slice(s_slice);
                        buf.push(0);
                        let hash = dalias_hash(buf.as_mut_ptr() as *mut c_char);

                        let mut map = INTERNAL_IPS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
                        let mut found = None;
                        for (i, e) in map.iter().enumerate() {
                            if e.hash == hash && e.string.as_bytes_with_nul() == buf.as_slice() { found = Some(i); break; }
                        }

                        let ip = if let Some(i) = found { make_internal_ip(i as u32) } else {
                            let idx = map.len();
                            if idx >= 0xFFFFFF { IPT4_INVALID() } else {
                                map.push(StringEntry { hash, string: CString::new(s_slice).unwrap_or_else(|_| CString::new("").unwrap()) });
                                make_internal_ip(idx as u32)
                            }
                        };

                        // send response header + ip
                        let mut out_msg: crate::rdns::at_msg = mem::zeroed();
                        out_msg.h.msgtype = crate::rdns::ATM_GETIP as u8;
                        out_msg.h.datalen = mem::size_of::<crate::rdns::ip_type4>() as u16;
                        out_msg.m.ip = ip;
                        let out_ptr = &out_msg as *const _ as *const u8;
                        let out_len = mem::size_of::<crate::rdns::at_msghdr>() + (out_msg.h.datalen as usize);
                        let _ = write_exact_fd(resp_write, out_ptr, out_len);
                    }
                    x if x == crate::rdns::ATM_GETNAME as i32 => {
                        let ip = msg.m.ip;
                        let idx = index_from_internal_ip(ip);
                        let mut out_msg: crate::rdns::at_msg = mem::zeroed();
                        out_msg.h.msgtype = crate::rdns::ATM_GETNAME as u8;
                        let map = INTERNAL_IPS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
                        if idx < map.len() {
                            let bytes = map[idx].string.as_bytes_with_nul();
                            let copy_len = std::cmp::min(bytes.len(), MSG_LEN_MAX + 1);
                            ptr::copy_nonoverlapping(bytes.as_ptr(), out_msg.m.host.as_mut_ptr() as *mut u8, copy_len);
                            out_msg.h.datalen = copy_len as u16;
                        } else {
                            out_msg.h.datalen = 0;
                        }
                        let out_ptr = &out_msg as *const _ as *const u8;
                        let out_len = mem::size_of::<crate::rdns::at_msghdr>() + (out_msg.h.datalen as usize);
                        let _ = write_exact_fd(resp_write, out_ptr, out_len);
                    }
                    x if x == crate::rdns::ATM_EXIT as i32 => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    });

    *handle_slot = Some(th);
}

#[no_mangle]
pub extern "C" fn at_get_host_for_ip(_ip: ip_type4, _readbuf: *mut c_char) -> usize {
    unsafe {
        if _readbuf.is_null() { return 0usize; }
        let idx = index_from_internal_ip(_ip);
        let guard = INTERNAL_IPS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
        if idx >= guard.len() { return 0usize; }
        let bytes = guard[idx].string.as_bytes_with_nul();
        // copy up to MSG_LEN_MAX (C checks lengths elsewhere)
        let copy_len = core::cmp::min(bytes.len(), MSG_LEN_MAX + 1);
        core::ptr::copy_nonoverlapping(bytes.as_ptr() as *const core::ffi::c_char, _readbuf, copy_len);
        copy_len - 1
    }
}

#[no_mangle]
pub extern "C" fn at_get_ip_for_host(_host: *mut c_char, _len: usize) -> ip_type4 {
    unsafe {
        if _host.is_null() || _len == 0 || _len > MSG_LEN_MAX { return IPT4_INVALID(); }

        let slice = slice::from_raw_parts(_host as *const u8, _len);
        let host_bytes = if slice.ends_with(&[0]) { &slice[..slice.len()-1] } else { slice };

        let mut buf = Vec::with_capacity(host_bytes.len()+1);
        buf.extend_from_slice(host_bytes);
        buf.push(0);

        let hash = dalias_hash(buf.as_mut_ptr() as *mut c_char);

        let mut guard = INTERNAL_IPS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
        for (i, entry) in guard.iter().enumerate() {
            if entry.hash == hash && entry.string.as_bytes_with_nul() == buf.as_slice() {
                return make_internal_ip(i as u32);
            }
        }

        let new_idx = guard.len();
        if new_idx >= 0xFFFFFD { return IPT4_INVALID(); }
        let entry = StringEntry { hash, string: CString::new(host_bytes).unwrap_or_else(|_| CString::new("").unwrap()) };
        guard.push(entry);
        make_internal_ip(new_idx as u32)
    }
}

#[no_mangle]
pub extern "C" fn at_close() {
    // send an exit header to the allocator thread
    unsafe {
        let mut hdr: crate::rdns::at_msghdr = mem::zeroed();
        hdr.msgtype = crate::rdns::ATM_EXIT as u8;
        hdr.datalen = 0;
        let hdr_ptr = &hdr as *const _ as *const u8;
        let _ = libc::write(req_pipefd[1], hdr_ptr as *const libc::c_void, mem::size_of::<crate::rdns::at_msghdr>());
    }

    // join the thread if present
    let guard = ALLOC_THREAD.get_or_init(|| Mutex::new(None));
    let mut opt = guard.lock().unwrap();
    if let Some(h) = opt.take() {
        let _ = h.join();
    }

    // close the pipes
    unsafe {
        libc::close(req_pipefd[0]);
        libc::close(req_pipefd[1]);
        libc::close(resp_pipefd[0]);
        libc::close(resp_pipefd[1]);
    }
}
