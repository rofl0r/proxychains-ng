extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fprintf(__stream: *mut FILE, __format: *const core::ffi::c_char, ...) -> core::ffi::c_int;
    fn snprintf(
        __s: *mut core::ffi::c_char,
        __maxlen: size_t,
        __format: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
    fn memcpy(
        __dest: *mut core::ffi::c_void,
        __src: *const core::ffi::c_void,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn memcmp(
        __s1: *const core::ffi::c_void,
        __s2: *const core::ffi::c_void,
        __n: size_t,
    ) -> core::ffi::c_int;
    fn strlen(__s: *const core::ffi::c_char) -> size_t;
    fn __errno_location() -> *mut core::ffi::c_int;
    fn getsockopt(
        __fd: core::ffi::c_int,
        __level: core::ffi::c_int,
        __optname: core::ffi::c_int,
        __optval: *mut core::ffi::c_void,
        __optlen: *mut socklen_t,
    ) -> core::ffi::c_int;
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    fn htons(__hostshort: uint16_t) -> uint16_t;
    fn inet_ntop(
        __af: core::ffi::c_int,
        __cp: *const core::ffi::c_void,
        __buf: *mut core::ffi::c_char,
        __len: socklen_t,
    ) -> *const core::ffi::c_char;
    fn inet_pton(
        __af: core::ffi::c_int,
        __cp: *const core::ffi::c_char,
        __buf: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn fcntl(__fd: core::ffi::c_int, __cmd: core::ffi::c_int, ...) -> core::ffi::c_int;
    fn connect_proxy_chain(
        sock: core::ffi::c_int,
        target_ip: ip_type,
        target_port: core::ffi::c_ushort,
        pd: *mut proxy_data,
        proxy_count: core::ffi::c_uint,
        ct: chain_type,
        max_chain: core::ffi::c_uint,
    ) -> core::ffi::c_int;
    fn proxy_gethostbyname(
        name: *const core::ffi::c_char,
        data: *mut gethostbyname_data,
    ) -> *mut hostent;
    fn proxy_gethostbyname_old(name: *const core::ffi::c_char) -> *mut hostent;
    fn proxy_getaddrinfo(
        node: *const core::ffi::c_char,
        service: *const core::ffi::c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> core::ffi::c_int;
    fn proxy_freeaddrinfo(res: *mut addrinfo);
    fn pc_stringfromipv4(
        ip_buf_4_bytes: *mut core::ffi::c_uchar,
        outbuf_16_bytes: *mut core::ffi::c_char,
    );
    static mut req_pipefd: [core::ffi::c_int; 2];
    static mut resp_pipefd: [core::ffi::c_int; 2];
}
pub type size_t = usize;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __off_t = core::ffi::c_long;
pub type __off64_t = core::ffi::c_long;
pub type __ssize_t = core::ffi::c_long;
pub type __socklen_t = core::ffi::c_uint;
// Use the libc::FILE type for a single canonical FILE across the crate.
pub type FILE = ::libc::FILE;
pub type ssize_t = __ssize_t;
pub type socklen_t = __socklen_t;
pub type close_t = Option<unsafe extern "C" fn(core::ffi::c_int) -> core::ffi::c_int>;
pub const DNSLF_RDNS_THREAD: dns_lookup_flavor = 2;
pub type dns_lookup_flavor = core::ffi::c_uint;
pub const DNSLF_RDNS_DAEMON: dns_lookup_flavor = 3;
pub const DNSLF_RDNS_START: dns_lookup_flavor = 2;
pub const DNSLF_FORKEXEC: dns_lookup_flavor = 1;
pub const DNSLF_LIBC: dns_lookup_flavor = 0;
pub type close_range_t = Option<
    unsafe extern "C" fn(
        core::ffi::c_uint,
        core::ffi::c_uint,
        core::ffi::c_int,
    ) -> core::ffi::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct close_range_args_t {
    pub first: core::ffi::c_uint,
    pub last: core::ffi::c_uint,
    pub flags: core::ffi::c_uint,
}
pub type pthread_once_t = core::ffi::c_int;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type __socket_type = core::ffi::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = core::ffi::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [core::ffi::c_char; 14],
}
pub type LibpcUnnamed = core::ffi::c_uint;
pub const MSG_CMSG_CLOEXEC: LibpcUnnamed = 1073741824;
pub const MSG_FASTOPEN: LibpcUnnamed = 536870912;
pub const MSG_ZEROCOPY: LibpcUnnamed = 67108864;
pub const MSG_BATCH: LibpcUnnamed = 262144;
pub const MSG_WAITFORONE: LibpcUnnamed = 65536;
pub const MSG_MORE: LibpcUnnamed = 32768;
pub const MSG_NOSIGNAL: LibpcUnnamed = 16384;
pub const MSG_ERRQUEUE: LibpcUnnamed = 8192;
pub const MSG_RST: LibpcUnnamed = 4096;
pub const MSG_CONFIRM: LibpcUnnamed = 2048;
pub const MSG_SYN: LibpcUnnamed = 1024;
pub const MSG_FIN: LibpcUnnamed = 512;
pub const MSG_WAITALL: LibpcUnnamed = 256;
pub const MSG_EOR: LibpcUnnamed = 128;
pub const MSG_DONTWAIT: LibpcUnnamed = 64;
pub const MSG_TRUNC: LibpcUnnamed = 32;
pub const MSG_PROXY: LibpcUnnamed = 16;
pub const MSG_CTRUNC: LibpcUnnamed = 8;
pub const MSG_TRYHARD: LibpcUnnamed = 4;
pub const MSG_DONTROUTE: LibpcUnnamed = 4;
pub const MSG_PEEK: LibpcUnnamed = 2;
pub const MSG_OOB: LibpcUnnamed = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: LibpcUnnamed0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union LibpcUnnamed0 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [core::ffi::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
pub const SUCCESS: LibpcUnnamed5 = 0;
pub type chain_type = core::ffi::c_uint;
pub const ROUND_ROBIN_TYPE: chain_type = 3;
pub const RANDOM_TYPE: chain_type = 2;
pub const STRICT_TYPE: chain_type = 1;
pub const DYNAMIC_TYPE: chain_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct proxy_data {
    pub ip: ip_type,
    pub port: core::ffi::c_ushort,
    pub pt: proxy_type,
    pub ps: proxy_state,
    pub user: [core::ffi::c_char; 256],
    pub pass: [core::ffi::c_char; 256],
}
pub type proxy_state = core::ffi::c_uint;
pub const BUSY_STATE: proxy_state = 3;
pub const BLOCKED_STATE: proxy_state = 2;
pub const DOWN_STATE: proxy_state = 1;
pub const PLAY_STATE: proxy_state = 0;
pub type proxy_type = core::ffi::c_uint;
pub const RAW_TYPE: proxy_type = 3;
pub const SOCKS5_TYPE: proxy_type = 2;
pub const SOCKS4_TYPE: proxy_type = 1;
pub const HTTP_TYPE: proxy_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ip_type {
    pub addr: LibpcUnnamed1,
    pub is_v6: core::ffi::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union LibpcUnnamed1 {
    pub v4: ip_type4,
    pub v6: [core::ffi::c_uchar; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union ip_type4 {
    pub octet: [core::ffi::c_uchar; 4],
    pub as_int: uint32_t,
}
pub type connect_t =
    Option<unsafe extern "C" fn(core::ffi::c_int, *const sockaddr, socklen_t) -> core::ffi::c_int>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LibpcUnnamed2 {
    pub in_addr: in_addr,
    pub in_mask: in_addr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union LibpcUnnamed3 {
    pub libpc_unnamed: LibpcUnnamed2,
    pub libpc_unnamed_0: LibpcUnnamed4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LibpcUnnamed4 {
    pub in6_addr: in6_addr,
    pub in6_prefix: core::ffi::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct localaddr_arg {
    pub family: sa_family_t,
    pub port: core::ffi::c_ushort,
    pub libpc_unnamed: LibpcUnnamed3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnat_arg {
    pub orig_dst: in_addr,
    pub new_dst: in_addr,
    pub orig_port: core::ffi::c_ushort,
    pub new_port: core::ffi::c_ushort,
}
pub type sendto_t = Option<
    unsafe extern "C" fn(
        core::ffi::c_int,
        *const core::ffi::c_void,
        size_t,
        core::ffi::c_int,
        *const sockaddr,
        socklen_t,
    ) -> ssize_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostent {
    pub h_name: *mut core::ffi::c_char,
    pub h_aliases: *mut *mut core::ffi::c_char,
    pub h_addrtype: core::ffi::c_int,
    pub h_length: core::ffi::c_int,
    pub h_addr_list: *mut *mut core::ffi::c_char,
}
pub type gethostbyaddr_t = Option<
    unsafe extern "C" fn(*const core::ffi::c_void, socklen_t, core::ffi::c_int) -> *mut hostent,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gethostbyname_data {
    pub hostent_space: hostent,
    pub resolved_addr: in_addr_t,
    pub resolved_addr_p: [*mut core::ffi::c_char; 2],
    pub addr_name: [core::ffi::c_char; 256],
}
pub type gethostbyname_t = Option<unsafe extern "C" fn(*const core::ffi::c_char) -> *mut hostent>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: core::ffi::c_int,
    pub ai_family: core::ffi::c_int,
    pub ai_socktype: core::ffi::c_int,
    pub ai_protocol: core::ffi::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut core::ffi::c_char,
    pub ai_next: *mut addrinfo,
}
pub type getaddrinfo_t = Option<
    unsafe extern "C" fn(
        *const core::ffi::c_char,
        *const core::ffi::c_char,
        *const addrinfo,
        *mut *mut addrinfo,
    ) -> core::ffi::c_int,
>;
pub type freeaddrinfo_t = Option<unsafe extern "C" fn(*mut addrinfo) -> ()>;
pub type getnameinfo_t = Option<
    unsafe extern "C" fn(
        *const sockaddr,
        socklen_t,
        *mut core::ffi::c_char,
        socklen_t,
        *mut core::ffi::c_char,
        socklen_t,
        core::ffi::c_int,
    ) -> core::ffi::c_int,
>;
pub type LibpcUnnamed5 = core::ffi::c_uint;
pub const BLOCKED: LibpcUnnamed5 = 5;
pub const CHAIN_EMPTY: LibpcUnnamed5 = 4;
pub const CHAIN_DOWN: LibpcUnnamed5 = 3;
pub const SOCKET_ERROR: LibpcUnnamed5 = 2;
pub const MEMORY_FAIL: LibpcUnnamed5 = 1;
pub const CHAR_BIT: core::ffi::c_int = __CHAR_BIT__;
pub const ECONNREFUSED: core::ffi::c_int = 111 as core::ffi::c_int;
pub const EINPROGRESS: core::ffi::c_int = 115 as core::ffi::c_int;
pub const SOL_SOCKET: core::ffi::c_int = 1 as core::ffi::c_int;
pub const SO_TYPE: core::ffi::c_int = 3 as core::ffi::c_int;
pub const EBADF: core::ffi::c_int = 9 as core::ffi::c_int;
pub const ENOMEM: core::ffi::c_int = 12 as core::ffi::c_int;
pub const PF_INET: core::ffi::c_int = 2 as core::ffi::c_int;
pub const PF_INET6: core::ffi::c_int = 10 as core::ffi::c_int;
pub const AF_INET: core::ffi::c_int = PF_INET;
pub const AF_INET6: core::ffi::c_int = PF_INET6;
pub const NULL: *mut core::ffi::c_void = 0 as *mut core::ffi::c_void;
pub const EAI_FAMILY: core::ffi::c_int = -(6 as core::ffi::c_int);
pub const EAI_OVERFLOW: core::ffi::c_int = -(12 as core::ffi::c_int);
pub const O_NONBLOCK: core::ffi::c_int = 0o4000 as core::ffi::c_int;
pub const F_GETFL: core::ffi::c_int = 3 as core::ffi::c_int;
pub const F_SETFL: core::ffi::c_int = 4 as core::ffi::c_int;
pub const PTHREAD_ONCE_INIT: core::ffi::c_int = 0 as core::ffi::c_int;
#[no_mangle]
pub static mut true_close: close_t = None;
#[no_mangle]
pub static mut true_close_range: close_range_t = None;
#[no_mangle]
pub static mut true_connect: connect_t = None;
#[no_mangle]
pub static mut true_gethostbyname: gethostbyname_t = None;
#[no_mangle]
pub static mut true_getaddrinfo: getaddrinfo_t = None;
#[no_mangle]
pub static mut true_freeaddrinfo: freeaddrinfo_t = None;
#[no_mangle]
pub static mut true_getnameinfo: getnameinfo_t = None;
#[no_mangle]
pub static mut true_gethostbyaddr: gethostbyaddr_t = None;
#[no_mangle]
pub static mut true_sendto: sendto_t = None;
#[no_mangle]
pub static mut tcp_read_time_out: core::ffi::c_int = 0;
#[no_mangle]
pub static mut tcp_connect_time_out: core::ffi::c_int = 0;
#[no_mangle]
pub static mut proxychains_ct: chain_type = DYNAMIC_TYPE;
#[no_mangle]
pub static mut proxychains_pd: [proxy_data; 512] = [proxy_data {
    ip: ip_type {
        addr: LibpcUnnamed1 {
            v4: ip_type4 { octet: [0; 4] },
        },
        is_v6: 0,
    },
    port: 0,
    pt: HTTP_TYPE,
    ps: PLAY_STATE,
    user: [0; 256],
    pass: [0; 256],
}; 512];
#[no_mangle]
pub static mut proxychains_proxy_count: core::ffi::c_uint = 0 as core::ffi::c_uint;
#[no_mangle]
pub static mut proxychains_proxy_offset: core::ffi::c_uint = 0 as core::ffi::c_uint;
#[no_mangle]
pub static mut proxychains_got_chain_data: core::ffi::c_int = 0 as core::ffi::c_int;
#[no_mangle]
pub static mut proxychains_max_chain: core::ffi::c_uint = 1 as core::ffi::c_uint;
#[no_mangle]
pub static mut proxychains_quiet_mode: core::ffi::c_int = 0 as core::ffi::c_int;
#[no_mangle]
pub static mut proxychains_verbose_debug: core::ffi::c_int = 0 as core::ffi::c_int;
#[no_mangle]
pub static mut proxychains_resolver: dns_lookup_flavor = DNSLF_LIBC;
#[no_mangle]
pub static mut localnet_addr: [localaddr_arg; 64] = [localaddr_arg {
    family: 0,
    port: 0,
    libpc_unnamed: LibpcUnnamed3 {
        libpc_unnamed: LibpcUnnamed2 {
            in_addr: in_addr { s_addr: 0 },
            in_mask: in_addr { s_addr: 0 },
        },
    },
}; 64];
#[no_mangle]
pub static mut num_localnet_addr: size_t = 0 as size_t;
unsafe fn load_sym(
    symname: *const core::ffi::c_char,
    _proxyfunc: *const core::ffi::c_void,
    is_mandatory: core::ffi::c_int,
) -> *mut core::ffi::c_void {
    let funcptr = libc::dlsym(libc::RTLD_NEXT, symname as *const core::ffi::c_char);
    if funcptr.is_null() {
        if is_mandatory != 0 {
            let _err = libc::dlerror();
            fprintf(
                stderr,
                b"Cannot load symbol '%s' %s\n\0" as *const u8 as *mut core::ffi::c_char,
                symname,
            );
            libc::exit(1);
        }
        return funcptr as *mut core::ffi::c_void;
    }
    return funcptr as *mut core::ffi::c_void;
}

pub unsafe fn setup_hooks() {
    if true_connect.is_none() {
        let s = b"connect\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, connect as *const core::ffi::c_void, 1);
        true_connect = Some(std::mem::transmute(f));
    }
    if true_sendto.is_none() {
        let s = b"sendto\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, sendto as *const core::ffi::c_void, 1);
        true_sendto = Some(std::mem::transmute(f));
    }
    if true_gethostbyname.is_none() {
        let s = b"gethostbyname\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, gethostbyname as *const core::ffi::c_void, 1);
        true_gethostbyname = Some(std::mem::transmute(f));
    }
    if true_getaddrinfo.is_none() {
        let s = b"getaddrinfo\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, getaddrinfo as *const core::ffi::c_void, 1);
        true_getaddrinfo = Some(std::mem::transmute(f));
    }
    if true_freeaddrinfo.is_none() {
        let s = b"freeaddrinfo\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, freeaddrinfo as *const core::ffi::c_void, 1);
        true_freeaddrinfo = Some(std::mem::transmute(f));
    }
    if true_getnameinfo.is_none() {
        let s = b"getnameinfo\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, getnameinfo as *const core::ffi::c_void, 1);
        true_getnameinfo = Some(std::mem::transmute(f));
    }
    if true_gethostbyaddr.is_none() {
        let s = b"gethostbyaddr\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, gethostbyaddr as *const core::ffi::c_void, 1);
        true_gethostbyaddr = Some(std::mem::transmute(f));
    }
    if true_close.is_none() {
        let s = b"close\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, close as *const core::ffi::c_void, 1);
        true_close = Some(std::mem::transmute(f));
    }
    if true_close_range.is_none() {
        let s = b"close_range\0".as_ptr() as *const core::ffi::c_char;
        let f = load_sym(s, close_range as *const core::ffi::c_void, 0);
        true_close_range = Some(std::mem::transmute(f));
    }
}

#[no_mangle]
pub unsafe extern "C" fn do_init() {
    use core::ffi::CStr;
    // set defaults
    tcp_read_time_out = 4 * 1000;
    tcp_connect_time_out = 10 * 1000;
    proxychains_ct = DYNAMIC_TYPE;

    // initialize core and hooks
    crate::core::core_initialize();
    // quiet mode
    let envptr = libc::getenv(crate::common::PROXYCHAINS_QUIET_MODE_ENV_VAR.as_ptr());
    if !envptr.is_null() && *envptr as u8 == b'1' {
        proxychains_quiet_mode = 1;
    }
    // log init (print using proxychains_write_log so it's consistent with C output/prefix)
    extern "C" {
        fn proxychains_get_version() -> *const core::ffi::c_char;
    }
    // NOTE: we preserve the env-driven quiet-mode check above before printing
    // ensure verbose debug is off by default; allow enabling with env PROXYCHAINS_VERBOSE_DEBUG=1
    proxychains_verbose_debug = 0;
    let vptr = libc::getenv(b"PROXYCHAINS_VERBOSE_DEBUG\0".as_ptr() as *const core::ffi::c_char);
    if !vptr.is_null() && *vptr as u8 == b'1' {
        proxychains_verbose_debug = 1;
    }
    crate::core::proxychains_write_log(
        b"[proxychains] DLL init: proxychains-ng %s\n\0" as *const u8 as *const core::ffi::c_char
            as *mut core::ffi::c_char,
        proxychains_get_version(),
    );
    setup_hooks();

    // read config and populate proxy list (simple parser for ProxyList)
    let mut buf: [core::ffi::c_char; 512] = [0; 512];
    let pathptr = crate::common::get_config_path(
        libc::getenv(crate::common::PROXYCHAINS_CONF_FILE_ENV_VAR.as_ptr()),
        buf.as_mut_ptr(),
        buf.len(),
    );
    if !pathptr.is_null() {
        if let Ok(path) = CStr::from_ptr(pathptr).to_str() {
            if let Ok(s) = std::fs::read_to_string(path) {
                let mut in_list = false;
                // Keep track of hostnames that need RDNS mapping deferred until after rdns_init
                let mut deferred_hosts: Vec<Option<String>> = vec![None; proxychains_pd.len()];
                for line in s.lines() {
                    let mut trimmed = line.trim();
                    if trimmed.starts_with('#') || trimmed.is_empty() {
                        continue;
                    }
                    if trimmed == "[ProxyList]" {
                        in_list = true;
                        continue;
                    }
                    if !in_list {
                        if trimmed == "dynamic_chain" {
                            proxychains_ct = DYNAMIC_TYPE;
                        } else if trimmed == "strict_chain" {
                            proxychains_ct = STRICT_TYPE;
                        } else if trimmed == "random_chain" {
                            proxychains_ct = RANDOM_TYPE;
                        } else if trimmed == "round_robin_chain" {
                            proxychains_ct = ROUND_ROBIN_TYPE;
                        } else if trimmed == "proxy_dns_old" {
                            /* match C implementation: select fork/exec resolver */
                            proxychains_resolver = DNSLF_FORKEXEC;
                        } else if trimmed == "proxy_dns" {
                            proxychains_resolver = DNSLF_RDNS_THREAD;
                        } else if trimmed.starts_with("proxy_dns_daemon") {
                            /* accept: proxy_dns_daemon <ip>:<port> - otherwise error and exit(1) */
                            let parts: Vec<&str> = trimmed.split_whitespace().collect();
                            if parts.len() < 2 {
                                fprintf(
                                    stderr,
                                    b"proxy_dns_daemon format error\n\0" as *const u8
                                        as *const core::ffi::c_char,
                                );
                                libc::exit(1);
                            }
                            if let Some(hostport) = parts.get(1) {
                                if let Some((addr, p)) = hostport.split_once(":") {
                                    let portnum = match p.parse::<u16>() {
                                        Ok(v) => v,
                                        Err(_) => {
                                            fprintf(
                                                stderr,
                                                b"proxy_dns_daemon format error\n\0" as *const u8
                                                    as *const core::ffi::c_char,
                                            );
                                            libc::exit(1);
                                        }
                                    };
                                    let mut rdns_server: crate::rdns::sockaddr_in =
                                        std::mem::zeroed();
                                    rdns_server.sin_family = libc::AF_INET as u16;
                                    // parse IP
                                    let caddr = std::ffi::CString::new(addr).unwrap_or_default();
                                    let ret = inet_pton(
                                        libc::AF_INET,
                                        caddr.as_ptr(),
                                        &mut rdns_server.sin_addr as *mut _
                                            as *mut core::ffi::c_void,
                                    );
                                    if ret <= 0 {
                                        fprintf(
                                            stderr,
                                            b"bogus proxy_dns_daemon address\n\0" as *const u8
                                                as *const core::ffi::c_char,
                                        );
                                        libc::exit(1);
                                    }
                                    rdns_server.sin_port = portnum.to_be();
                                    proxychains_resolver = DNSLF_RDNS_DAEMON;
                                    crate::rdns::rdns_set_daemon(
                                        &mut rdns_server as *mut crate::rdns::sockaddr_in,
                                    );
                                } else {
                                    fprintf(
                                        stderr,
                                        b"proxy_dns_daemon format error\n\0" as *const u8
                                            as *const core::ffi::c_char,
                                    );
                                    libc::exit(1);
                                }
                            }
                        } else if trimmed == "quiet_mode" {
                            proxychains_quiet_mode = 1;
                        }
                        continue;
                    }
                    // parse entry, format: type host port [user] [pass]
                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    if tokens.len() < 3 {
                        continue;
                    }
                    let typ = tokens[0];
                    let host = tokens[1];
                    let port: u16 = tokens[2].parse().unwrap_or(0);
                    let mut userbuf: [core::ffi::c_char; 256] = [0; 256];
                    let mut passbuf: [core::ffi::c_char; 256] = [0; 256];
                    if tokens.len() >= 4 {
                        let user = tokens[3];
                        let cuser = std::ffi::CString::new(user).unwrap();
                        let bytes = cuser.as_bytes_with_nul();
                        for i in 0..bytes.len().min(256) {
                            userbuf[i] = bytes[i] as core::ffi::c_char;
                        }
                    }
                    if tokens.len() >= 5 {
                        let pass = tokens[4];
                        let cpass = std::ffi::CString::new(pass).unwrap();
                        let bytes = cpass.as_bytes_with_nul();
                        for i in 0..bytes.len().min(256) {
                            passbuf[i] = bytes[i] as core::ffi::c_char;
                        }
                    }
                    if proxychains_proxy_count as usize >= proxychains_pd.len() {
                        break;
                    }
                    let idx = proxychains_proxy_count as usize;
                    // set user/pass
                    proxychains_pd[idx].user = userbuf;
                    proxychains_pd[idx].pass = passbuf;
                    proxychains_pd[idx].ps = PLAY_STATE;
                    proxychains_pd[idx].port = htons(port);
                    // parse host to set proxy ip
                    let c_host = std::ffi::CString::new(host).unwrap_or_default();
                    // numeric ipv4 address?
                    if crate::common::pc_isnumericipv4(c_host.as_ptr()) != 0 {
                        if let Ok(parsed) = host.parse::<std::net::Ipv4Addr>() {
                            let octets = parsed.octets();
                            unsafe {
                                proxychains_pd[idx].ip.addr.v4.octet =
                                    [octets[0], octets[1], octets[2], octets[3]];
                                proxychains_pd[idx].ip.is_v6 = 0;
                            }
                        }
                    } else {
                        // if not numeric and strict and rdns configured we can use rdns_get_ip_for_host
                        if proxychains_ct == STRICT_TYPE
                            && proxychains_resolver >= DNSLF_RDNS_START
                            && (idx as core::ffi::c_int) > 0
                        {
                            // Defer RDNS lookup until after rdns_init to avoid race/threading issues.
                            deferred_hosts[idx] = Some(host.to_string());
                        }
                    }
                    if typ == "http" {
                        proxychains_pd[idx].pt = HTTP_TYPE;
                    } else if typ == "socks4" {
                        proxychains_pd[idx].pt = SOCKS4_TYPE;
                    } else if typ == "socks5" {
                        proxychains_pd[idx].pt = SOCKS5_TYPE;
                    }
                    // TODO: add debug log for parsed proxies when needed
                    proxychains_proxy_count += 1;
                }
                // after parsing, set final flags and then init rdns
                /* quiet mode parsed (no debug output) */
                proxychains_got_chain_data = 1;
                // init rdns
                crate::rdns::rdns_init(proxychains_resolver);
                // process deferred hostnames for proxies
                for (i, maybe_host) in deferred_hosts.iter().enumerate() {
                    if let Some(hostname) = maybe_host {
                        let c_host = std::ffi::CString::new(hostname.as_str()).unwrap_or_default();
                        let ip4 = crate::rdns::rdns_get_ip_for_host(
                            c_host.as_ptr() as *mut core::ffi::c_char,
                            hostname.len() as size_t,
                        );
                        let ip4_int: u32 = unsafe { ip4.as_int };
                        unsafe {
                            proxychains_pd[i].ip.addr.v4.as_int = ip4_int;
                            proxychains_pd[i].ip.is_v6 = 0;
                        }
                        if ip4_int == crate::core::IPT4_INVALID.as_int {
                            eprintln!("proxy {} has invalid value or is not numeric", hostname);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }
    proxychains_got_chain_data = 1;
    // finished init
    init_l = 1;
    // start remote DNS
    crate::rdns::rdns_init(proxychains_resolver);
}

// Call do_init at library load time
#[ctor::ctor]
fn gcc_init() {
    unsafe {
        do_init();
    }
}
#[no_mangle]
pub static mut dnats: [dnat_arg; 64] = [dnat_arg {
    orig_dst: in_addr { s_addr: 0 },
    new_dst: in_addr { s_addr: 0 },
    orig_port: 0,
    new_port: 0,
}; 64];
#[no_mangle]
pub static mut num_dnats: size_t = 0 as size_t;
#[no_mangle]
pub static mut remote_dns_subnet: core::ffi::c_uint = 224 as core::ffi::c_uint;
#[no_mangle]
pub static mut init_once: pthread_once_t = PTHREAD_ONCE_INIT;
static mut init_l: core::ffi::c_int = 0 as core::ffi::c_int;
static mut close_fds: [core::ffi::c_int; 16] = [0; 16];
static mut close_fds_cnt: core::ffi::c_int = 0 as core::ffi::c_int;
static mut close_range_buffer: [close_range_args_t; 16] = [close_range_args_t {
    first: 0,
    last: 0,
    flags: 0,
}; 16];
static mut close_range_buffer_cnt: core::ffi::c_int = 0 as core::ffi::c_int;
#[no_mangle]
pub unsafe extern "C" fn close(mut fd: core::ffi::c_int) -> core::ffi::c_int {
    if init_l == 0 {
        if !(close_fds_cnt as usize
            >= (::core::mem::size_of::<[core::ffi::c_int; 16]>() as usize)
                .wrapping_div(::core::mem::size_of::<core::ffi::c_int>() as usize))
        {
            let fresh0 = close_fds_cnt;
            close_fds_cnt = close_fds_cnt + 1;
            close_fds[fresh0 as usize] = fd;
            *__errno_location() = 0 as core::ffi::c_int;
            return 0 as core::ffi::c_int;
        }
    } else {
        if proxychains_resolver as core::ffi::c_uint
            != DNSLF_RDNS_THREAD as core::ffi::c_int as core::ffi::c_uint
        {
            return true_close.expect("non-null function pointer")(fd);
        }
        if fd != req_pipefd[0 as core::ffi::c_int as usize]
            && fd != req_pipefd[1 as core::ffi::c_int as usize]
            && fd != resp_pipefd[0 as core::ffi::c_int as usize]
            && fd != resp_pipefd[1 as core::ffi::c_int as usize]
        {
            return true_close.expect("non-null function pointer")(fd);
        }
    }
    *__errno_location() = EBADF;
    return -(1 as core::ffi::c_int);
}
unsafe extern "C" fn is_v4inv6(mut a: *const in6_addr) -> core::ffi::c_int {
    return (memcmp(
        ((*a).__in6_u.__u6_addr8).as_ptr() as *const core::ffi::c_void,
        b"\0\0\0\0\0\0\0\0\0\0\xFF\xFF\0" as *const u8 as *const core::ffi::c_char
            as *const core::ffi::c_void,
        12 as size_t,
    ) == 0) as core::ffi::c_int;
}
unsafe extern "C" fn intsort(mut a: *mut core::ffi::c_int, mut n: core::ffi::c_int) {
    let mut i: core::ffi::c_int = 0;
    let mut j: core::ffi::c_int = 0;
    let mut s: core::ffi::c_int = 0;
    i = 0 as core::ffi::c_int;
    while i < n {
        j = i + 1 as core::ffi::c_int;
        while j < n {
            if *a.offset(j as isize) < *a.offset(i as isize) {
                s = *a.offset(i as isize);
                *a.offset(i as isize) = *a.offset(j as isize);
                *a.offset(j as isize) = s;
            }
            j += 1;
        }
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn close_range(
    mut first: core::ffi::c_uint,
    mut last: core::ffi::c_uint,
    mut flags: core::ffi::c_int,
) -> core::ffi::c_int {
    if true_close_range.is_none() {
        fprintf(
            stderr,
            b"Calling close_range, but this platform does not provide this system call. \0"
                as *const u8 as *const core::ffi::c_char,
        );
        return -(1 as core::ffi::c_int);
    }
    if init_l == 0 {
        if close_range_buffer_cnt as usize
            >= (::core::mem::size_of::<[close_range_args_t; 16]>() as usize)
                .wrapping_div(::core::mem::size_of::<close_range_args_t>() as usize)
        {
            *__errno_location() = ENOMEM;
            return -(1 as core::ffi::c_int);
        }
        let fresh1 = close_range_buffer_cnt;
        close_range_buffer_cnt = close_range_buffer_cnt + 1;
        let mut i: core::ffi::c_int = fresh1;
        close_range_buffer[i as usize].first = first;
        close_range_buffer[i as usize].last = last;
        close_range_buffer[i as usize].flags = flags as core::ffi::c_uint;
        let ref mut fresh2 = *__errno_location();
        *fresh2 = 0 as core::ffi::c_int;
        return *fresh2;
    }
    if proxychains_resolver as core::ffi::c_uint
        != DNSLF_RDNS_THREAD as core::ffi::c_int as core::ffi::c_uint
    {
        return true_close_range.expect("non-null function pointer")(first, last, flags);
    }
    let mut res: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut uerrno: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut i_0: core::ffi::c_int = 0;
    let mut protected_fds: [core::ffi::c_int; 4] = [
        req_pipefd[0 as core::ffi::c_int as usize],
        req_pipefd[1 as core::ffi::c_int as usize],
        resp_pipefd[0 as core::ffi::c_int as usize],
        resp_pipefd[1 as core::ffi::c_int as usize],
    ];
    intsort(protected_fds.as_mut_ptr(), 4 as core::ffi::c_int);
    let mut next_fd_to_close: core::ffi::c_int = first as core::ffi::c_int;
    i_0 = 0 as core::ffi::c_int;
    while i_0 < 4 as core::ffi::c_int {
        if !((protected_fds[i_0 as usize] as core::ffi::c_uint) < first
            || protected_fds[i_0 as usize] as core::ffi::c_uint > last)
        {
            let mut prev: core::ffi::c_int = (if i_0 == 0 as core::ffi::c_int
                || (protected_fds[(i_0 - 1 as core::ffi::c_int) as usize] as core::ffi::c_uint)
                    < first
            {
                first
            } else {
                (protected_fds[(i_0 - 1 as core::ffi::c_int) as usize] + 1 as core::ffi::c_int)
                    as core::ffi::c_uint
            }) as core::ffi::c_int;
            if prev != protected_fds[i_0 as usize] {
                if -(1 as core::ffi::c_int)
                    == true_close_range.expect("non-null function pointer")(
                        prev as core::ffi::c_uint,
                        (protected_fds[i_0 as usize] - 1 as core::ffi::c_int) as core::ffi::c_uint,
                        flags,
                    )
                {
                    res = -(1 as core::ffi::c_int);
                    uerrno = *__errno_location();
                }
            }
            next_fd_to_close = protected_fds[i_0 as usize] + 1 as core::ffi::c_int;
        }
        i_0 += 1;
    }
    if next_fd_to_close as core::ffi::c_uint <= last {
        if -(1 as core::ffi::c_int)
            == true_close_range.expect("non-null function pointer")(
                next_fd_to_close as core::ffi::c_uint,
                last,
                flags,
            )
        {
            res = -(1 as core::ffi::c_int);
            uerrno = *__errno_location();
        }
    }
    *__errno_location() = uerrno;
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn connect(
    mut sock: core::ffi::c_int,
    mut addr: *const sockaddr,
    mut len: core::ffi::c_uint,
) -> core::ffi::c_int {
    let mut socktype: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut flags: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut ret: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut optlen: socklen_t = 0 as socklen_t;
    let mut dest_ip: ip_type = ip_type {
        addr: LibpcUnnamed1 {
            v4: ip_type4 { octet: [0; 4] },
        },
        is_v6: 0,
    };
    let mut p_addr_in: *mut in_addr = 0 as *mut in_addr;
    let mut p_addr_in6: *mut in6_addr = 0 as *mut in6_addr;
    let mut dnat: *mut dnat_arg = 0 as *mut dnat_arg;
    let mut port: core::ffi::c_ushort = 0;
    let mut i: size_t = 0;
    let mut remote_dns_connect: core::ffi::c_int = 0 as core::ffi::c_int;
    optlen = ::core::mem::size_of::<core::ffi::c_int>() as socklen_t;
    let mut fam: sa_family_t = (*(addr as *mut sockaddr_in)).sin_family;
    getsockopt(
        sock,
        SOL_SOCKET,
        SO_TYPE,
        &mut socktype as *mut core::ffi::c_int as *mut core::ffi::c_void,
        &mut optlen,
    );
    if !((fam as core::ffi::c_int == AF_INET || fam as core::ffi::c_int == AF_INET6)
        && socktype == SOCK_STREAM as core::ffi::c_int)
    {
        return true_connect.expect("non-null function pointer")(sock, addr, len as socklen_t);
    }
    dest_ip.is_v6 = (fam as core::ffi::c_int == AF_INET6) as core::ffi::c_int as core::ffi::c_char;
    let mut v6: core::ffi::c_int = dest_ip.is_v6 as core::ffi::c_int;
    p_addr_in = &mut (*(addr as *mut sockaddr_in)).sin_addr;
    p_addr_in6 = &mut (*(addr as *mut sockaddr_in6)).sin6_addr;
    port = (if v6 == 0 {
        ntohs((*(addr as *mut sockaddr_in)).sin_port as uint16_t) as core::ffi::c_int
    } else {
        ntohs((*(addr as *mut sockaddr_in6)).sin6_port as uint16_t) as core::ffi::c_int
    }) as core::ffi::c_ushort;
    let mut v4inv6: in_addr = in_addr { s_addr: 0 };
    if v6 != 0 && is_v4inv6(p_addr_in6) != 0 {
        memcpy(
            &mut v4inv6.s_addr as *mut in_addr_t as *mut core::ffi::c_void,
            &mut *((*p_addr_in6).__in6_u.__u6_addr8)
                .as_mut_ptr()
                .offset(12 as core::ffi::c_int as isize) as *mut uint8_t
                as *const core::ffi::c_void,
            4 as size_t,
        );
        dest_ip.is_v6 = 0 as core::ffi::c_char;
        v6 = dest_ip.is_v6 as core::ffi::c_int;
        p_addr_in = &mut v4inv6;
    }
    if v6 == 0
        && memcmp(
            p_addr_in as *const core::ffi::c_void,
            b"\0\0\0\0\0" as *const u8 as *const core::ffi::c_char as *const core::ffi::c_void,
            4 as size_t,
        ) == 0
    {
        *__errno_location() = ECONNREFUSED;
        return -(1 as core::ffi::c_int);
    }
    remote_dns_connect = (v6 == 0
        && ntohl((*p_addr_in).s_addr as uint32_t) >> 24 as core::ffi::c_int
            == remote_dns_subnet as uint32_t) as core::ffi::c_int;
    if v6 == 0 {
        i = 0 as size_t;
        while i < num_dnats && remote_dns_connect == 0 && dnat.is_null() {
            if dnats[i as usize].orig_dst.s_addr == (*p_addr_in).s_addr {
                if dnats[i as usize].orig_port as core::ffi::c_int != 0
                    && dnats[i as usize].orig_port as core::ffi::c_int == port as core::ffi::c_int
                {
                    dnat = &mut *dnats.as_mut_ptr().offset(i as isize) as *mut dnat_arg;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    if v6 == 0 {
        i = 0 as size_t;
        while i < num_dnats && remote_dns_connect == 0 && dnat.is_null() {
            if dnats[i as usize].orig_dst.s_addr == (*p_addr_in).s_addr {
                if dnats[i as usize].orig_port == 0 {
                    dnat = &mut *dnats.as_mut_ptr().offset(i as isize) as *mut dnat_arg;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    if !dnat.is_null() {
        p_addr_in = &mut (*dnat).new_dst;
        if (*dnat).new_port != 0 {
            port = (*dnat).new_port;
        }
    }
    let mut current_block_48: u64;
    i = 0 as size_t;
    while i < num_localnet_addr && remote_dns_connect == 0 {
        if !(localnet_addr[i as usize].port as core::ffi::c_int != 0
            && localnet_addr[i as usize].port as core::ffi::c_int != port as core::ffi::c_int)
        {
            if !(localnet_addr[i as usize].family as core::ffi::c_int
                != (if v6 != 0 { AF_INET6 } else { AF_INET }))
            {
                if v6 != 0 {
                    let mut prefix_bytes: size_t = (localnet_addr[i as usize]
                        .libpc_unnamed
                        .libpc_unnamed_0
                        .in6_prefix
                        as core::ffi::c_int
                        / CHAR_BIT) as size_t;
                    let mut prefix_bits: size_t = (localnet_addr[i as usize]
                        .libpc_unnamed
                        .libpc_unnamed_0
                        .in6_prefix
                        as core::ffi::c_int
                        % CHAR_BIT) as size_t;
                    if prefix_bytes != 0
                        && memcmp(
                            ((*p_addr_in6).__in6_u.__u6_addr8).as_mut_ptr()
                                as *const core::ffi::c_void,
                            (localnet_addr[i as usize]
                                .libpc_unnamed
                                .libpc_unnamed_0
                                .in6_addr
                                .__in6_u
                                .__u6_addr8)
                                .as_mut_ptr()
                                as *const core::ffi::c_void,
                            prefix_bytes,
                        ) != 0 as core::ffi::c_int
                    {
                        current_block_48 = 10758786907990354186;
                    } else if prefix_bits != 0
                        && ((*p_addr_in6).__in6_u.__u6_addr8[prefix_bytes as usize]
                            as core::ffi::c_int
                            ^ localnet_addr[i as usize]
                                .libpc_unnamed
                                .libpc_unnamed_0
                                .in6_addr
                                .__in6_u
                                .__u6_addr8[prefix_bytes as usize]
                                as core::ffi::c_int)
                            >> (CHAR_BIT as size_t).wrapping_sub(prefix_bits)
                            != 0
                    {
                        current_block_48 = 10758786907990354186;
                    } else {
                        current_block_48 = 1724319918354933278;
                    }
                } else if ((*p_addr_in).s_addr
                    ^ localnet_addr[i as usize]
                        .libpc_unnamed
                        .libpc_unnamed
                        .in_addr
                        .s_addr)
                    & localnet_addr[i as usize]
                        .libpc_unnamed
                        .libpc_unnamed
                        .in_mask
                        .s_addr
                    != 0
                {
                    current_block_48 = 10758786907990354186;
                } else {
                    current_block_48 = 1724319918354933278;
                }
                match current_block_48 {
                    10758786907990354186 => {}
                    _ => {
                        return true_connect.expect("non-null function pointer")(
                            sock,
                            addr,
                            len as socklen_t,
                        );
                    }
                }
            }
        }
        i = i.wrapping_add(1);
    }
    flags = fcntl(sock, F_GETFL, 0 as core::ffi::c_int);
    if flags & O_NONBLOCK != 0 {
        fcntl(sock, F_SETFL, (O_NONBLOCK == 0) as core::ffi::c_int);
    }
    memcpy(
        (dest_ip.addr.v6).as_mut_ptr() as *mut core::ffi::c_void,
        if v6 != 0 {
            p_addr_in6 as *mut core::ffi::c_void
        } else {
            p_addr_in as *mut core::ffi::c_void
        },
        (if v6 != 0 {
            16 as core::ffi::c_int
        } else {
            4 as core::ffi::c_int
        }) as size_t,
    );
    ret = connect_proxy_chain(
        sock,
        dest_ip,
        htons(port as uint16_t) as core::ffi::c_ushort,
        proxychains_pd.as_mut_ptr(),
        proxychains_proxy_count,
        proxychains_ct,
        proxychains_max_chain,
    );
    fcntl(sock, F_SETFL, flags);
    if ret != SUCCESS as core::ffi::c_int {
        *__errno_location() = ECONNREFUSED;
    }
    return ret;
}
static mut ghbndata: gethostbyname_data = gethostbyname_data {
    hostent_space: hostent {
        h_name: 0 as *const core::ffi::c_char as *mut core::ffi::c_char,
        h_aliases: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
    },
    resolved_addr: 0,
    resolved_addr_p: [0 as *const core::ffi::c_char as *mut core::ffi::c_char; 2],
    addr_name: [0; 256],
};
#[no_mangle]
pub unsafe extern "C" fn gethostbyname(mut name: *const core::ffi::c_char) -> *mut hostent {
    if true_gethostbyname.is_none() {
        crate::libproxychains::setup_hooks();
    }
    if proxychains_resolver as core::ffi::c_uint
        == DNSLF_FORKEXEC as core::ffi::c_int as core::ffi::c_uint
    {
        return proxy_gethostbyname_old(name);
    } else if proxychains_resolver as core::ffi::c_uint
        == DNSLF_LIBC as core::ffi::c_int as core::ffi::c_uint
    {
        return true_gethostbyname.expect("non-null function pointer")(name);
    } else {
        return proxy_gethostbyname(name, &mut ghbndata);
    };
}
#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    mut node: *const core::ffi::c_char,
    mut service: *const core::ffi::c_char,
    mut hints: *const addrinfo,
    mut res: *mut *mut addrinfo,
) -> core::ffi::c_int {
    if true_getaddrinfo.is_none() {
        crate::libproxychains::setup_hooks();
    }
    if proxychains_resolver as core::ffi::c_uint
        != DNSLF_LIBC as core::ffi::c_int as core::ffi::c_uint
    {
        return proxy_getaddrinfo(node, service, hints, res);
    } else {
        return true_getaddrinfo.expect("non-null function pointer")(node, service, hints, res);
    };
}
#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(mut res: *mut addrinfo) {
    if true_freeaddrinfo.is_none() {
        crate::libproxychains::setup_hooks();
    }
    if proxychains_resolver as core::ffi::c_uint
        == DNSLF_LIBC as core::ffi::c_int as core::ffi::c_uint
    {
        true_freeaddrinfo.expect("non-null function pointer")(res);
    } else {
        proxy_freeaddrinfo(res);
    };
}
#[no_mangle]
pub unsafe extern "C" fn getnameinfo(
    mut sa: *const sockaddr,
    mut salen: socklen_t,
    mut host: *mut core::ffi::c_char,
    mut hostlen: socklen_t,
    mut serv: *mut core::ffi::c_char,
    mut servlen: socklen_t,
    mut flags: core::ffi::c_int,
) -> core::ffi::c_int {
    if true_getnameinfo.is_none() {
        crate::libproxychains::setup_hooks();
    }
    if proxychains_resolver as core::ffi::c_uint
        == DNSLF_LIBC as core::ffi::c_int as core::ffi::c_uint
    {
        return true_getnameinfo.expect("non-null function pointer")(
            sa, salen, host, hostlen, serv, servlen, flags,
        );
    } else {
        if salen == 0
            || !((*(sa as *mut sockaddr_in)).sin_family as core::ffi::c_int == AF_INET
                || (*(sa as *mut sockaddr_in)).sin_family as core::ffi::c_int == AF_INET6)
        {
            return EAI_FAMILY;
        }
        let mut v6: core::ffi::c_int = ((*(sa as *mut sockaddr_in)).sin_family as core::ffi::c_int
            == AF_INET6) as core::ffi::c_int;
        if (salen as usize)
            < (if v6 != 0 {
                ::core::mem::size_of::<sockaddr_in6>() as usize
            } else {
                ::core::mem::size_of::<sockaddr_in>() as usize
            })
        {
            return EAI_FAMILY;
        }
        if hostlen != 0 {
            let mut v4inv6buf: [core::ffi::c_uchar; 4] = [0; 4];
            let mut ip: *const core::ffi::c_void = if v6 != 0 {
                &mut (*(sa as *mut sockaddr_in6)).sin6_addr as *mut in6_addr
                    as *mut core::ffi::c_void
            } else {
                &mut (*(sa as *mut sockaddr_in)).sin_addr as *mut in_addr as *mut core::ffi::c_void
            };
            let mut scopeid: core::ffi::c_uint = 0 as core::ffi::c_uint;
            if v6 != 0 {
                if is_v4inv6(&mut (*(sa as *mut sockaddr_in6)).sin6_addr) != 0 {
                    memcpy(
                        v4inv6buf.as_mut_ptr() as *mut core::ffi::c_void,
                        &mut *((*(sa as *mut sockaddr_in6)).sin6_addr.__in6_u.__u6_addr8)
                            .as_mut_ptr()
                            .offset(12 as core::ffi::c_int as isize)
                            as *mut uint8_t as *const core::ffi::c_void,
                        4 as size_t,
                    );
                    ip = v4inv6buf.as_mut_ptr() as *const core::ffi::c_void;
                    v6 = 0 as core::ffi::c_int;
                } else {
                    scopeid = (*(sa as *mut sockaddr_in6)).sin6_scope_id as core::ffi::c_uint;
                }
            }
            if (inet_ntop(if v6 != 0 { AF_INET6 } else { AF_INET }, ip, host, hostlen)).is_null() {
                return EAI_OVERFLOW;
            }
            if scopeid != 0 {
                let mut l: size_t = strlen(host);
                if snprintf(
                    host.offset(l as isize),
                    (hostlen as size_t).wrapping_sub(l),
                    b"%%%u\0" as *const u8 as *const core::ffi::c_char,
                    scopeid,
                ) as size_t
                    >= (hostlen as size_t).wrapping_sub(l)
                {
                    return EAI_OVERFLOW;
                }
            }
        }
        if servlen != 0 {
            if snprintf(
                serv,
                servlen as size_t,
                b"%d\0" as *const u8 as *const core::ffi::c_char,
                ntohs((*(sa as *mut sockaddr_in)).sin_port as uint16_t) as core::ffi::c_int,
            ) as socklen_t
                >= servlen
            {
                return EAI_OVERFLOW;
            }
        }
    }
    return 0 as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr(
    mut addr: *const core::ffi::c_void,
    mut len: socklen_t,
    mut type_0: core::ffi::c_int,
) -> *mut hostent {
    static mut buf: [core::ffi::c_char; 16] = [0; 16];
    static mut ipv4: [core::ffi::c_char; 4] = [0; 4];
    static mut list: [*mut core::ffi::c_char; 2] =
        [0 as *const core::ffi::c_char as *mut core::ffi::c_char; 2];
    static mut aliases: [*mut core::ffi::c_char; 1] =
        [0 as *const core::ffi::c_char as *mut core::ffi::c_char; 1];
    static mut he: hostent = hostent {
        h_name: 0 as *const core::ffi::c_char as *mut core::ffi::c_char,
        h_aliases: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
    };
    if proxychains_resolver as core::ffi::c_uint
        == DNSLF_LIBC as core::ffi::c_int as core::ffi::c_uint
    {
        return true_gethostbyaddr.expect("non-null function pointer")(addr, len, type_0);
    } else {
        if len != 4 as socklen_t {
            return 0 as *mut hostent;
        }
        he.h_name = buf.as_mut_ptr();
        memcpy(
            ipv4.as_mut_ptr() as *mut core::ffi::c_void,
            addr,
            4 as size_t,
        );
        list[0 as core::ffi::c_int as usize] = ipv4.as_mut_ptr();
        list[1 as core::ffi::c_int as usize] = 0 as *mut core::ffi::c_char;
        he.h_addr_list = list.as_mut_ptr();
        he.h_addrtype = AF_INET;
        aliases[0 as core::ffi::c_int as usize] = 0 as *mut core::ffi::c_char;
        he.h_aliases = aliases.as_mut_ptr();
        he.h_length = 4 as core::ffi::c_int;
        pc_stringfromipv4(addr as *mut core::ffi::c_uchar, buf.as_mut_ptr());
        return &mut he;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sendto(
    mut sockfd: core::ffi::c_int,
    mut buf: *const core::ffi::c_void,
    mut len: size_t,
    mut flags: core::ffi::c_int,
    mut dest_addr: *const sockaddr,
    mut addrlen: socklen_t,
) -> ssize_t {
    if flags & MSG_FASTOPEN as core::ffi::c_int != 0 {
        if connect(sockfd, dest_addr, addrlen as core::ffi::c_uint) == 0
            && *__errno_location() != EINPROGRESS
        {
            return -(1 as core::ffi::c_int) as ssize_t;
        }
        dest_addr = 0 as *const sockaddr;
        addrlen = 0 as socklen_t;
        flags &= !(MSG_FASTOPEN as core::ffi::c_int);
    }
    return true_sendto.expect("non-null function pointer")(
        sockfd, buf, len, flags, dest_addr, addrlen,
    );
}
pub const __CHAR_BIT__: core::ffi::c_int = 8 as core::ffi::c_int;
