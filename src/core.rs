extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> core::ffi::c_int;
    fn fprintf(__stream: *mut FILE, __format: *const core::ffi::c_char, ...) -> core::ffi::c_int;
    fn snprintf(
        __s: *mut core::ffi::c_char,
        __maxlen: size_t,
        __format: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
    fn vsnprintf(
        __s: *mut core::ffi::c_char,
        __maxlen: size_t,
        __format: *const core::ffi::c_char,
        __arg: ::core::ffi::VaList,
    ) -> core::ffi::c_int;
    fn perror(__s: *const core::ffi::c_char);
    fn close(__fd: core::ffi::c_int) -> core::ffi::c_int;
    fn read(__fd: core::ffi::c_int, __buf: *mut core::ffi::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: core::ffi::c_int, __buf: *const core::ffi::c_void, __n: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut core::ffi::c_int) -> core::ffi::c_int;
    fn usleep(__useconds: __useconds_t) -> core::ffi::c_int;
    fn dup2(__fd: core::ffi::c_int, __fd2: core::ffi::c_int) -> core::ffi::c_int;
    fn execlp(
        __file: *const core::ffi::c_char,
        __arg: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
    fn fork() -> __pid_t;
    fn gethostname(__name: *mut core::ffi::c_char, __len: size_t) -> core::ffi::c_int;
    fn atoi(__nptr: *const core::ffi::c_char) -> core::ffi::c_int;
    fn rand() -> core::ffi::c_int;
    fn calloc(__nmemb: size_t, __size: size_t) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn exit(__status: core::ffi::c_int) -> !;
    fn memcpy(
        __dest: *mut core::ffi::c_void,
        __src: *const core::ffi::c_void,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn memset(
        __s: *mut core::ffi::c_void,
        __c: core::ffi::c_int,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn strcpy(
        __dest: *mut core::ffi::c_char,
        __src: *const core::ffi::c_char,
    ) -> *mut core::ffi::c_char;
    fn strcmp(__s1: *const core::ffi::c_char, __s2: *const core::ffi::c_char) -> core::ffi::c_int;
    fn strchr(__s: *const core::ffi::c_char, __c: core::ffi::c_int) -> *mut core::ffi::c_char;
    fn strlen(__s: *const core::ffi::c_char) -> size_t;
    fn __errno_location() -> *mut core::ffi::c_int;
    fn socket(
        __domain: core::ffi::c_int,
        __type: core::ffi::c_int,
        __protocol: core::ffi::c_int,
    ) -> core::ffi::c_int;
    fn send(
        __fd: core::ffi::c_int,
        __buf: *const core::ffi::c_void,
        __n: size_t,
        __flags: core::ffi::c_int,
    ) -> ssize_t;
    fn getsockopt(
        __fd: core::ffi::c_int,
        __level: core::ffi::c_int,
        __optname: core::ffi::c_int,
        __optval: *mut core::ffi::c_void,
        __optlen: *mut socklen_t,
    ) -> core::ffi::c_int;
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    fn htons(__hostshort: uint16_t) -> uint16_t;
    fn gethostent() -> *mut hostent;
    fn getservbyname(
        __name: *const core::ffi::c_char,
        __proto: *const core::ffi::c_char,
    ) -> *mut servent;
    fn inet_addr(__cp: *const core::ffi::c_char) -> in_addr_t;
    fn inet_ntoa(__in: in_addr) -> *mut core::ffi::c_char;
    fn inet_pton(
        __af: core::ffi::c_int,
        __cp: *const core::ffi::c_char,
        __buf: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn inet_ntop(
        __af: core::ffi::c_int,
        __cp: *const core::ffi::c_void,
        __buf: *mut core::ffi::c_char,
        __len: socklen_t,
    ) -> *const core::ffi::c_char;
    fn inet_aton(__cp: *const core::ffi::c_char, __inp: *mut in_addr) -> core::ffi::c_int;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: core::ffi::c_int) -> core::ffi::c_int;
    fn waitpid(
        __pid: __pid_t,
        __stat_loc: *mut core::ffi::c_int,
        __options: core::ffi::c_int,
    ) -> __pid_t;
    fn fcntl(__fd: core::ffi::c_int, __cmd: core::ffi::c_int, ...) -> core::ffi::c_int;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut core::ffi::c_void) -> core::ffi::c_int;
    fn __assert_fail(
        __assertion: *const core::ffi::c_char,
        __file: *const core::ffi::c_char,
        __line: core::ffi::c_uint,
        __function: *const core::ffi::c_char,
    ) -> !;
    static mut true_connect: connect_t;
    fn pc_isnumericipv4(ipstring: *const core::ffi::c_char) -> core::ffi::c_int;
    fn rdns_get_host_for_ip(ip: ip_type4, readbuf: *mut core::ffi::c_char) -> size_t;
    fn rdns_get_ip_for_host(host: *mut core::ffi::c_char, len: size_t) -> ip_type4;
    static mut proxychains_resolver: dns_lookup_flavor;
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> core::ffi::c_int;
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> core::ffi::c_int;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> core::ffi::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> core::ffi::c_int;
    static mut tcp_read_time_out: core::ffi::c_int;
    static mut tcp_connect_time_out: core::ffi::c_int;
    static mut proxychains_quiet_mode: core::ffi::c_int;
    static mut proxychains_proxy_offset: core::ffi::c_uint;
    static mut remote_dns_subnet: core::ffi::c_uint;
    fn hostsreader_get_numeric_ip_for_name(name: *const core::ffi::c_char) -> ip_type4;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: core::ffi::c_uint,
    pub fp_offset: core::ffi::c_uint,
    pub overflow_arg_area: *mut core::ffi::c_void,
    pub reg_save_area: *mut core::ffi::c_void,
}
pub type size_t = usize;
pub type __gnuc_va_list = __builtin_va_list;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __off_t = core::ffi::c_long;
pub type __off64_t = core::ffi::c_long;
pub type __pid_t = core::ffi::c_int;
pub type __time_t = core::ffi::c_long;
pub type __useconds_t = core::ffi::c_uint;
pub type __suseconds_t = core::ffi::c_long;
pub type __ssize_t = core::ffi::c_long;
pub type __socklen_t = core::ffi::c_uint;
// Use libc::FILE as the canonical FILE type instead of local duplicate
// _IO_FILE structs which lead to clashing extern declarations across
// modules. Keeping FILE as libc::FILE keeps signatures consistent.
pub type FILE = ::libc::FILE;
pub type va_list = __gnuc_va_list;
pub type ssize_t = __ssize_t;
pub type pid_t = __pid_t;
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: core::ffi::c_int,
    pub __count: core::ffi::c_uint,
    pub __owner: core::ffi::c_int,
    pub __nusers: core::ffi::c_uint,
    pub __kind: core::ffi::c_int,
    pub __spins: core::ffi::c_short,
    pub __elision: core::ffi::c_short,
    pub __list: __pthread_list_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [core::ffi::c_char; 4],
    pub __align: core::ffi::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [core::ffi::c_char; 40],
    pub __align: core::ffi::c_long,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [core::ffi::c_char; 118],
    pub __ss_align: core::ffi::c_ulong,
}
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
    pub __in6_u: CoreUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union CoreUnnamed {
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
pub type CoreUnnamed0 = core::ffi::c_uint;
pub const IPPROTO_MAX: CoreUnnamed0 = 263;
pub const IPPROTO_MPTCP: CoreUnnamed0 = 262;
pub const IPPROTO_RAW: CoreUnnamed0 = 255;
pub const IPPROTO_ETHERNET: CoreUnnamed0 = 143;
pub const IPPROTO_MPLS: CoreUnnamed0 = 137;
pub const IPPROTO_UDPLITE: CoreUnnamed0 = 136;
pub const IPPROTO_SCTP: CoreUnnamed0 = 132;
pub const IPPROTO_L2TP: CoreUnnamed0 = 115;
pub const IPPROTO_COMP: CoreUnnamed0 = 108;
pub const IPPROTO_PIM: CoreUnnamed0 = 103;
pub const IPPROTO_ENCAP: CoreUnnamed0 = 98;
pub const IPPROTO_BEETPH: CoreUnnamed0 = 94;
pub const IPPROTO_MTP: CoreUnnamed0 = 92;
pub const IPPROTO_AH: CoreUnnamed0 = 51;
pub const IPPROTO_ESP: CoreUnnamed0 = 50;
pub const IPPROTO_GRE: CoreUnnamed0 = 47;
pub const IPPROTO_RSVP: CoreUnnamed0 = 46;
pub const IPPROTO_IPV6: CoreUnnamed0 = 41;
pub const IPPROTO_DCCP: CoreUnnamed0 = 33;
pub const IPPROTO_TP: CoreUnnamed0 = 29;
pub const IPPROTO_IDP: CoreUnnamed0 = 22;
pub const IPPROTO_UDP: CoreUnnamed0 = 17;
pub const IPPROTO_PUP: CoreUnnamed0 = 12;
pub const IPPROTO_EGP: CoreUnnamed0 = 8;
pub const IPPROTO_TCP: CoreUnnamed0 = 6;
pub const IPPROTO_IPIP: CoreUnnamed0 = 4;
pub const IPPROTO_IGMP: CoreUnnamed0 = 2;
pub const IPPROTO_ICMP: CoreUnnamed0 = 1;
pub const IPPROTO_IP: CoreUnnamed0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostent {
    pub h_name: *mut core::ffi::c_char,
    pub h_aliases: *mut *mut core::ffi::c_char,
    pub h_addrtype: core::ffi::c_int,
    pub h_length: core::ffi::c_int,
    pub h_addr_list: *mut *mut core::ffi::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct servent {
    pub s_name: *mut core::ffi::c_char,
    pub s_aliases: *mut *mut core::ffi::c_char,
    pub s_port: core::ffi::c_int,
    pub s_proto: *mut core::ffi::c_char,
}
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
pub type nfds_t = core::ffi::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: core::ffi::c_int,
    pub events: core::ffi::c_short,
    pub revents: core::ffi::c_short,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union ip_type4 {
    pub octet: [core::ffi::c_uchar; 4],
    pub as_int: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ip_type {
    pub addr: CoreUnnamed1,
    pub is_v6: core::ffi::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union CoreUnnamed1 {
    pub v4: ip_type4,
    pub v6: [core::ffi::c_uchar; 16],
}
pub type CoreUnnamed2 = core::ffi::c_uint;
pub const BLOCKED: CoreUnnamed2 = 5;
pub const CHAIN_EMPTY: CoreUnnamed2 = 4;
pub const CHAIN_DOWN: CoreUnnamed2 = 3;
pub const SOCKET_ERROR: CoreUnnamed2 = 2;
pub const MEMORY_FAIL: CoreUnnamed2 = 1;
pub const SUCCESS: CoreUnnamed2 = 0;
pub type proxy_type = core::ffi::c_uint;
pub const RAW_TYPE: proxy_type = 3;
pub const SOCKS5_TYPE: proxy_type = 2;
pub const SOCKS4_TYPE: proxy_type = 1;
pub const HTTP_TYPE: proxy_type = 0;
pub type chain_type = core::ffi::c_uint;
pub const ROUND_ROBIN_TYPE: chain_type = 3;
pub const RANDOM_TYPE: chain_type = 2;
pub const STRICT_TYPE: chain_type = 1;
pub const DYNAMIC_TYPE: chain_type = 0;
pub type proxy_state = core::ffi::c_uint;
pub const BUSY_STATE: proxy_state = 3;
pub const BLOCKED_STATE: proxy_state = 2;
pub const DOWN_STATE: proxy_state = 1;
pub const PLAY_STATE: proxy_state = 0;
pub type select_type = core::ffi::c_uint;
pub const FIFOLY: select_type = 1;
pub const RANDOMLY: select_type = 0;
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
pub const DNSLF_RDNS_START: dns_lookup_flavor = 2;
pub type dns_lookup_flavor = core::ffi::c_uint;
pub const DNSLF_RDNS_DAEMON: dns_lookup_flavor = 3;
pub const DNSLF_RDNS_THREAD: dns_lookup_flavor = 2;
pub const DNSLF_FORKEXEC: dns_lookup_flavor = 1;
pub const DNSLF_LIBC: dns_lookup_flavor = 0;
pub type connect_t =
    Option<unsafe extern "C" fn(core::ffi::c_int, *const sockaddr, socklen_t) -> core::ffi::c_int>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gethostbyname_data {
    pub hostent_space: hostent,
    pub resolved_addr: in_addr_t,
    pub resolved_addr_p: [*mut core::ffi::c_char; 2],
    pub addr_name: [core::ffi::c_char; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo_data {
    pub addrinfo_space: addrinfo,
    pub sockaddr_space: sockaddr_storage,
    pub addr_name: [core::ffi::c_char; 256],
}
pub const ENOENT: core::ffi::c_int = 2 as core::ffi::c_int;
pub const EINTR: core::ffi::c_int = 4 as core::ffi::c_int;
pub const ETIMEDOUT: core::ffi::c_int = 110 as core::ffi::c_int;
pub const ECONNREFUSED: core::ffi::c_int = 111 as core::ffi::c_int;
pub const EINPROGRESS: core::ffi::c_int = 115 as core::ffi::c_int;
pub const PF_INET: core::ffi::c_int = 2 as core::ffi::c_int;
pub const PF_INET6: core::ffi::c_int = 10 as core::ffi::c_int;
pub const AF_INET: core::ffi::c_int = PF_INET;
pub const AF_INET6: core::ffi::c_int = PF_INET6;
pub const SOL_SOCKET: core::ffi::c_int = 1 as core::ffi::c_int;
pub const SO_ERROR: core::ffi::c_int = 4 as core::ffi::c_int;
pub const AI_PASSIVE: core::ffi::c_int = 0x1 as core::ffi::c_int;
pub const AI_NUMERICHOST: core::ffi::c_int = 0x4 as core::ffi::c_int;
pub const AI_V4MAPPED: core::ffi::c_int = 0x8 as core::ffi::c_int;
pub const AI_ADDRCONFIG: core::ffi::c_int = 0x20 as core::ffi::c_int;
pub const EAI_NONAME: core::ffi::c_int = -(2 as core::ffi::c_int);
pub const EAI_MEMORY: core::ffi::c_int = -(10 as core::ffi::c_int);
pub const POLLIN: core::ffi::c_int = 0x1 as core::ffi::c_int;
pub const POLLOUT: core::ffi::c_int = 0x4 as core::ffi::c_int;
pub const O_NONBLOCK: core::ffi::c_int = 0o4000 as core::ffi::c_int;
pub const F_SETFD: core::ffi::c_int = 2 as core::ffi::c_int;
pub const F_SETFL: core::ffi::c_int = 4 as core::ffi::c_int;
pub const FD_CLOEXEC: core::ffi::c_int = 1 as core::ffi::c_int;
pub const __ASSERT_FUNCTION: [core::ffi::c_char; 95] = unsafe {
    ::core::mem::transmute::<
        [u8; 95],
        [core::ffi::c_char; 95],
    >(
        *b"int proxy_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **)\0",
    )
};
pub const IPT4_INVALID: ip_type4 = ip_type4 {
    as_int: -(1 as core::ffi::c_int) as uint32_t,
};
pub const IPT4_LOCALHOST: ip_type4 = ip_type4 {
    octet: [
        127 as core::ffi::c_int as core::ffi::c_uchar,
        0 as core::ffi::c_int as core::ffi::c_uchar,
        0 as core::ffi::c_int as core::ffi::c_uchar,
        1 as core::ffi::c_int as core::ffi::c_uchar,
    ],
};
pub const NULL: *mut core::ffi::c_void = 0 as *mut core::ffi::c_void;
unsafe extern "C" fn poll_retry(
    mut fds: *mut pollfd,
    mut nfsd: nfds_t,
    mut timeout: core::ffi::c_int,
) -> core::ffi::c_int {
    let mut ret: core::ffi::c_int = 0;
    let mut time_remain: core::ffi::c_int = timeout;
    let mut time_elapsed: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut start_time: timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut tv: timeval = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    gettimeofday(&mut start_time, NULL);
    loop {
        ret = poll(fds, nfsd, time_remain);
        gettimeofday(&mut tv, NULL);
        time_elapsed = ((tv.tv_sec as __suseconds_t - start_time.tv_sec as __suseconds_t)
            * 1000 as __suseconds_t
            + (tv.tv_usec - start_time.tv_usec) / 1000 as __suseconds_t)
            as core::ffi::c_int;
        time_remain = timeout - time_elapsed;
        if !(ret == -(1 as core::ffi::c_int)
            && *__errno_location() == EINTR
            && time_remain > 0 as core::ffi::c_int)
        {
            break;
        }
    }
    return ret;
}
unsafe extern "C" fn encode_base_64(
    mut src: *mut core::ffi::c_char,
    mut dest: *mut core::ffi::c_char,
    mut max_len: core::ffi::c_int,
) {
    static mut base64: [core::ffi::c_char; 65] = unsafe {
        ::core::mem::transmute::<[u8; 65], [core::ffi::c_char; 65]>(
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0",
        )
    };
    let mut n: core::ffi::c_int = 0;
    let mut l: core::ffi::c_int = 0;
    let mut i: core::ffi::c_int = 0;
    l = strlen(src) as core::ffi::c_int;
    max_len = (max_len - 1 as core::ffi::c_int) / 4 as core::ffi::c_int;
    i = 0 as core::ffi::c_int;
    while i < max_len {
        match l {
            0 => {}
            1 => {
                n = (*src.offset(0 as core::ffi::c_int as isize) as core::ffi::c_int)
                    << 16 as core::ffi::c_int;
                let fresh9 = dest;
                dest = dest.offset(1);
                *fresh9 = base64[(n >> 18 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh10 = dest;
                dest = dest.offset(1);
                *fresh10 =
                    base64[(n >> 12 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh11 = dest;
                dest = dest.offset(1);
                *fresh11 = '=' as i32 as core::ffi::c_char;
                let fresh12 = dest;
                dest = dest.offset(1);
                *fresh12 = '=' as i32 as core::ffi::c_char;
            }
            2 => {
                n = (*src.offset(0 as core::ffi::c_int as isize) as core::ffi::c_int)
                    << 16 as core::ffi::c_int
                    | (*src.offset(1 as core::ffi::c_int as isize) as core::ffi::c_int)
                        << 8 as core::ffi::c_int;
                let fresh13 = dest;
                dest = dest.offset(1);
                *fresh13 =
                    base64[(n >> 18 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh14 = dest;
                dest = dest.offset(1);
                *fresh14 =
                    base64[(n >> 12 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh15 = dest;
                dest = dest.offset(1);
                *fresh15 = base64[(n >> 6 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh16 = dest;
                dest = dest.offset(1);
                *fresh16 = '=' as i32 as core::ffi::c_char;
            }
            _ => {
                n = (*src.offset(0 as core::ffi::c_int as isize) as core::ffi::c_int)
                    << 16 as core::ffi::c_int
                    | (*src.offset(1 as core::ffi::c_int as isize) as core::ffi::c_int)
                        << 8 as core::ffi::c_int
                    | *src.offset(2 as core::ffi::c_int as isize) as core::ffi::c_int;
                let fresh17 = dest;
                dest = dest.offset(1);
                *fresh17 =
                    base64[(n >> 18 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh18 = dest;
                dest = dest.offset(1);
                *fresh18 =
                    base64[(n >> 12 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh19 = dest;
                dest = dest.offset(1);
                *fresh19 = base64[(n >> 6 as core::ffi::c_int & 0o77 as core::ffi::c_int) as usize];
                let fresh20 = dest;
                dest = dest.offset(1);
                *fresh20 = base64[(n & 0o77 as core::ffi::c_int) as usize];
            }
        }
        if l < 3 as core::ffi::c_int {
            break;
        }
        i += 1;
        src = src.offset(3 as core::ffi::c_int as isize);
        l -= 3 as core::ffi::c_int;
    }
    let fresh21 = dest;
    dest = dest.offset(1);
    *fresh21 = 0 as core::ffi::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn proxychains_write_log(mut str: *mut core::ffi::c_char, mut args: ...) {
    let mut buff: [core::ffi::c_char; 4096] = [0; 4096];
    let mut arglist: ::core::ffi::VaListImpl;
    if proxychains_quiet_mode == 0 {
        arglist = args.clone();
        vsnprintf(
            buff.as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 4096]>() as size_t,
            str,
            arglist.as_va_list(),
        );
        fprintf(
            stderr,
            b"%s\0" as *const u8 as *const core::ffi::c_char,
            buff.as_mut_ptr(),
        );
        fflush(stderr);
    }
}
unsafe extern "C" fn write_n_bytes(
    mut fd: core::ffi::c_int,
    mut buff: *mut core::ffi::c_char,
    mut size: size_t,
) -> core::ffi::c_int {
    let mut i: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut wrote: size_t = 0 as size_t;
    loop {
        i = write(
            fd,
            &mut *buff.offset(wrote as isize) as *mut core::ffi::c_char as *const core::ffi::c_void,
            size.wrapping_sub(wrote),
        ) as core::ffi::c_int;
        if i <= 0 as core::ffi::c_int {
            return i;
        }
        wrote = wrote.wrapping_add(i as size_t);
        if wrote == size {
            return wrote as core::ffi::c_int;
        }
    }
}
unsafe extern "C" fn read_n_bytes(
    mut fd: core::ffi::c_int,
    mut buff: *mut core::ffi::c_char,
    mut size: size_t,
) -> core::ffi::c_int {
    let mut ready: core::ffi::c_int = 0;
    let mut i: size_t = 0;
    let mut pfd: [pollfd; 1] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 1];
    pfd[0 as core::ffi::c_int as usize].fd = fd;
    pfd[0 as core::ffi::c_int as usize].events = POLLIN as core::ffi::c_short;
    i = 0 as size_t;
    while i < size {
        pfd[0 as core::ffi::c_int as usize].revents = 0 as core::ffi::c_short;
        ready = poll_retry(pfd.as_mut_ptr(), 1 as nfds_t, tcp_read_time_out);
        if ready != 1 as core::ffi::c_int
            || pfd[0 as core::ffi::c_int as usize].revents as core::ffi::c_int & POLLIN == 0
            || 1 as ssize_t
                != read(
                    fd,
                    &mut *buff.offset(i as isize) as *mut core::ffi::c_char
                        as *mut core::ffi::c_void,
                    1 as size_t,
                )
        {
            return -(1 as core::ffi::c_int);
        }
        i = i.wrapping_add(1);
    }
    return size as core::ffi::c_int;
}
unsafe extern "C" fn timed_connect(
    mut sock: core::ffi::c_int,
    mut addr: *const sockaddr,
    mut len: socklen_t,
) -> core::ffi::c_int {
    let mut ret: core::ffi::c_int = 0;
    let mut value: core::ffi::c_int = 0;
    let mut value_len: socklen_t = 0;
    let mut pfd: [pollfd; 1] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 1];
    pfd[0 as core::ffi::c_int as usize].fd = sock;
    pfd[0 as core::ffi::c_int as usize].events = POLLOUT as core::ffi::c_short;
    fcntl(sock, F_SETFL, O_NONBLOCK);
    if crate::libproxychains::proxychains_verbose_debug != 0 {
        proxychains_write_log(
            b"[proxychains-debug] timed_connect: sock=%d non-blocking\n\0" as *const u8
                as *const core::ffi::c_char as *mut core::ffi::c_char,
            sock,
        );
    }
    if true_connect.is_none() {
        crate::libproxychains::setup_hooks();
    }
    ret = true_connect.expect("non-null function pointer")(sock, addr, len);
    if ret == -(1 as core::ffi::c_int) && *__errno_location() == EINPROGRESS {
        if crate::libproxychains::proxychains_verbose_debug != 0 {
            proxychains_write_log(
                b"[proxychains-debug] timed_connect: connect in progress (sock=%d) errno=%d\n\0"
                    as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char,
                sock,
                *__errno_location(),
            );
        }
        ret = poll_retry(pfd.as_mut_ptr(), 1 as nfds_t, tcp_connect_time_out);
        if ret == 1 as core::ffi::c_int {
            value_len = ::core::mem::size_of::<socklen_t>() as socklen_t;
            getsockopt(
                sock,
                SOL_SOCKET,
                SO_ERROR,
                &mut value as *mut core::ffi::c_int as *mut core::ffi::c_void,
                &mut value_len,
            );
            if crate::libproxychains::proxychains_verbose_debug != 0 {
                proxychains_write_log(
                    b"[proxychains-debug] timed_connect: getsockopt SO_ERROR=%d\n\0" as *const u8
                        as *const core::ffi::c_char as *mut core::ffi::c_char,
                    value,
                );
            }
            if value == 0 {
                ret = 0 as core::ffi::c_int;
            } else {
                ret = -(1 as core::ffi::c_int);
            }
        } else {
            ret = -(1 as core::ffi::c_int);
        }
    } else if ret != 0 as core::ffi::c_int {
        ret = -(1 as core::ffi::c_int);
    }
    if crate::libproxychains::proxychains_verbose_debug != 0 {
        proxychains_write_log(
            b"[proxychains-debug] timed_connect: final ret=%d errno=%d sock=%d\n\0" as *const u8
                as *const core::ffi::c_char as *mut core::ffi::c_char,
            ret,
            *__errno_location(),
            sock,
        );
    }
    fcntl(sock, F_SETFL, (O_NONBLOCK == 0) as core::ffi::c_int);
    return ret;
}
pub const BUFF_SIZE: core::ffi::c_int = 1024 as core::ffi::c_int;
unsafe extern "C" fn tunnel_to(
    mut sock: core::ffi::c_int,
    mut ip: ip_type,
    mut port: core::ffi::c_ushort,
    mut pt: proxy_type,
    mut user: *mut core::ffi::c_char,
    mut pass: *mut core::ffi::c_char,
) -> core::ffi::c_int {
    let mut ulen: size_t = 0;
    let mut passlen: size_t = 0;
    let mut len: core::ffi::c_int = 0;
    let mut buff: [core::ffi::c_uchar; 1024] = [0; 1024];
    let mut ip_buf: [core::ffi::c_char; 46] = [0; 46];
    let mut v6: core::ffi::c_int = 0;
    let mut current_block: u64;
    let mut dns_name: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut hostnamebuf: [core::ffi::c_char; 256] = [0; 256];
    let mut dns_len: size_t = 0 as size_t;
    if ip.is_v6 == 0
        && proxychains_resolver as core::ffi::c_uint
            >= DNSLF_RDNS_START as core::ffi::c_int as core::ffi::c_uint
        && ip.addr.v4.octet[0 as core::ffi::c_int as usize] as core::ffi::c_uint
            == remote_dns_subnet
    {
        dns_len = rdns_get_host_for_ip(ip.addr.v4, hostnamebuf.as_mut_ptr());
        if dns_len == 0 {
            current_block = 4787357585276075074;
        } else {
            dns_name = hostnamebuf.as_mut_ptr();
            current_block = 11650488183268122163;
        }
    } else {
        current_block = 11650488183268122163;
    }
    match current_block {
        11650488183268122163 => {
            /* Debug: log tunnel target and dns name if available */
            let mut dns_ptr: *mut core::ffi::c_char = dns_name;
            if dns_ptr.is_null() {
                dns_ptr =
                    b"(none)\0" as *const u8 as *const core::ffi::c_char as *mut core::ffi::c_char;
            }
            if !(inet_ntop(
                if v6 != 0 { AF_INET6 } else { AF_INET },
                ip.addr.v6.as_mut_ptr() as *const core::ffi::c_void,
                ip_buf.as_mut_ptr(),
                ::core::mem::size_of::<[core::ffi::c_char; 46]>() as socklen_t,
            ))
            .is_null()
            {
                if crate::libproxychains::proxychains_verbose_debug != 0 {
                    proxychains_write_log(
                        b"[proxychains-debug] tunnel_to: sock=%d target=%s:%d proxy_type=%d dns=%s\n\0" as *const u8 as *const core::ffi::c_char as *mut core::ffi::c_char,
                        sock,
                        ip_buf.as_mut_ptr(),
                        htons(port) as core::ffi::c_int,
                        pt as core::ffi::c_int,
                        dns_ptr,
                    );
                }
            }
            ulen = strlen(user);
            passlen = strlen(pass);
            if ulen > 0xff as size_t || passlen > 0xff as size_t || dns_len > 0xff as size_t {
                proxychains_write_log(
                    b"[proxychains] error: maximum size of 255 for user/pass or domain name!\n\0"
                        as *const u8 as *const core::ffi::c_char
                        as *mut core::ffi::c_char,
                );
            } else {
                len = 0;
                buff = [0; 1024];
                ip_buf = [0; 46];
                v6 = ip.is_v6 as core::ffi::c_int;
                match pt as core::ffi::c_uint {
                    3 => {
                        current_block = 8588843005822345763;
                        match current_block {
                            8588843005822345763 => return SUCCESS as core::ffi::c_int,
                            14072441030219150333 => {
                                if v6 != 0 {
                                    proxychains_write_log(
                                        b"[proxychains] error: SOCKS4 doesn't support ipv6 addresses\n\0"
                                            as *const u8 as *const core::ffi::c_char
                                            as *mut core::ffi::c_char,
                                    );
                                } else {
                                    buff[0 as core::ffi::c_int as usize] = 4 as core::ffi::c_uchar;
                                    buff[1 as core::ffi::c_int as usize] = 1 as core::ffi::c_uchar;
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(2 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut port as *mut core::ffi::c_ushort
                                            as *const core::ffi::c_void,
                                        2 as size_t,
                                    );
                                    if dns_len != 0 {
                                        ip.addr.v4.octet[0 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[1 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[2 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[3 as core::ffi::c_int as usize] =
                                            1 as core::ffi::c_uchar;
                                    }
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(4 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut ip.addr.v4 as *mut ip_type4
                                            as *const core::ffi::c_void,
                                        4 as size_t,
                                    );
                                    len = ulen.wrapping_add(1 as size_t) as core::ffi::c_int;
                                    if len > 1 as core::ffi::c_int {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset(8 as core::ffi::c_int as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            user as *const core::ffi::c_void,
                                            len as size_t,
                                        );
                                    } else {
                                        buff[8 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                    }
                                    if dns_len != 0 {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset((8 as core::ffi::c_int + len) as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            dns_name as *const core::ffi::c_void,
                                            dns_len.wrapping_add(1 as size_t),
                                        );
                                        len = (len as size_t)
                                            .wrapping_add(dns_len.wrapping_add(1 as size_t))
                                            as core::ffi::c_int
                                            as core::ffi::c_int;
                                    }
                                    if !(len + 8 as core::ffi::c_int
                                        != write_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            (8 as core::ffi::c_int + len) as size_t,
                                        ))
                                    {
                                        if !(8 as core::ffi::c_int
                                            != read_n_bytes(
                                                sock,
                                                buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                8 as size_t,
                                            ))
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                || buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 90 as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                            return SUCCESS as core::ffi::c_int;
                                        }
                                    }
                                }
                            }
                            8457315219000651999 => {
                                if dns_len == 0 {
                                    if (inet_ntop(
                                        if v6 != 0 { AF_INET6 } else { AF_INET },
                                        (ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                                        ip_buf.as_mut_ptr(),
                                        ::core::mem::size_of::<[core::ffi::c_char; 46]>()
                                            as socklen_t,
                                    ))
                                    .is_null()
                                    {
                                        proxychains_write_log(
                                            b"[proxychains] error: ip address conversion failed\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char
                                                as *mut core::ffi::c_char,
                                        );
                                        current_block = 4787357585276075074;
                                    } else {
                                        dns_name = ip_buf.as_mut_ptr();
                                        current_block = 5783071609795492627;
                                    }
                                } else {
                                    current_block = 5783071609795492627;
                                }
                                match current_block {
                                    4787357585276075074 => {}
                                    _ => {
                                        let mut src: [core::ffi::c_char; 512] = [0; 512];
                                        let mut dst: [core::ffi::c_char; 2048] = [0; 2048];
                                        if ulen != 0 {
                                            snprintf(
                                                src.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 512]>()
                                                    as size_t,
                                                b"%s:%s\0" as *const u8 as *const core::ffi::c_char,
                                                user,
                                                pass,
                                            );
                                            encode_base_64(
                                                src.as_mut_ptr(),
                                                dst.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 2048]>()
                                                    as core::ffi::c_int,
                                            );
                                        } else {
                                            dst[0 as core::ffi::c_int as usize] =
                                                0 as core::ffi::c_char;
                                        }
                                        let mut hs_port: uint16_t = ntohs(port as uint16_t);
                                        len = snprintf(
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            ::core::mem::size_of::<[core::ffi::c_uchar; 1024]>()
                                                as size_t,
                                            b"CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            if ulen != 0 {
                                                b"Proxy-Authorization: Basic \0" as *const u8
                                                    as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                            dst.as_mut_ptr(),
                                            if ulen != 0 {
                                                b"\r\n\0" as *const u8 as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                        );
                                        if !(len < 0 as core::ffi::c_int
                                            || len as ssize_t
                                                != send(
                                                    sock,
                                                    buff.as_mut_ptr() as *const core::ffi::c_void,
                                                    len as size_t,
                                                    0 as core::ffi::c_int,
                                                ))
                                        {
                                            len = 0 as core::ffi::c_int;
                                            loop {
                                                if !(len < BUFF_SIZE) {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                                if !(1 as core::ffi::c_int
                                                    == read_n_bytes(
                                                        sock,
                                                        buff.as_mut_ptr().offset(len as isize)
                                                            as *mut core::ffi::c_char,
                                                        1 as size_t,
                                                    ))
                                                {
                                                    current_block = 4787357585276075074;
                                                    break;
                                                }
                                                len += 1;
                                                if len > 4 as core::ffi::c_int
                                                    && buff[(len - 1 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 2 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                    && buff[(len - 3 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 4 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    if len == BUFF_SIZE
                                                        || !(buff[9 as core::ffi::c_int as usize]
                                                            as core::ffi::c_int
                                                            == '2' as i32
                                                            && buff[10 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32
                                                            && buff[11 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32)
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    return SUCCESS as core::ffi::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                let mut n_methods: core::ffi::c_int = if ulen != 0 {
                                    2 as core::ffi::c_int
                                } else {
                                    1 as core::ffi::c_int
                                };
                                buff[0 as core::ffi::c_int as usize] = 5 as core::ffi::c_uchar;
                                buff[1 as core::ffi::c_int as usize] =
                                    n_methods as core::ffi::c_uchar;
                                buff[2 as core::ffi::c_int as usize] = 0 as core::ffi::c_uchar;
                                if ulen != 0 {
                                    buff[3 as core::ffi::c_int as usize] = 2 as core::ffi::c_uchar;
                                }
                                if !(2 as core::ffi::c_int + n_methods
                                    != write_n_bytes(
                                        sock,
                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                        (2 as core::ffi::c_int + n_methods) as size_t,
                                    ))
                                {
                                    if !(2 as core::ffi::c_int
                                        != read_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            2 as size_t,
                                        ))
                                    {
                                        if buff[0 as core::ffi::c_int as usize] as core::ffi::c_int
                                            != 5 as core::ffi::c_int
                                            || buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 2 as core::ffi::c_int
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 5 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 0xff as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                        } else {
                                            if buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 2 as core::ffi::c_int
                                            {
                                                let mut in_0: [core::ffi::c_char; 2] = [0; 2];
                                                let mut out: [core::ffi::c_char; 515] = [0; 515];
                                                let mut cur: *mut core::ffi::c_char =
                                                    out.as_mut_ptr();
                                                let mut c: size_t = 0;
                                                let fresh0 = cur;
                                                cur = cur.offset(1);
                                                *fresh0 = 1 as core::ffi::c_char;
                                                c = ulen & 0xff as size_t;
                                                let fresh1 = cur;
                                                cur = cur.offset(1);
                                                *fresh1 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    user as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                c = passlen & 0xff as size_t;
                                                let fresh2 = cur;
                                                cur = cur.offset(1);
                                                *fresh2 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    pass as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                if cur.offset_from(out.as_mut_ptr())
                                                    as core::ffi::c_long
                                                    != write_n_bytes(
                                                        sock,
                                                        out.as_mut_ptr(),
                                                        cur.offset_from(out.as_mut_ptr())
                                                            as core::ffi::c_long
                                                            as size_t,
                                                    )
                                                        as core::ffi::c_long
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if 2 as core::ffi::c_int
                                                    != read_n_bytes(
                                                        sock,
                                                        in_0.as_mut_ptr(),
                                                        2 as size_t,
                                                    )
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if !(in_0[0 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 5 as core::ffi::c_int
                                                    || in_0[0 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        == 1 as core::ffi::c_int)
                                                {
                                                    current_block = 4787357585276075074;
                                                } else {
                                                    if in_0[1 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        != 0 as core::ffi::c_int
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    current_block = 8464383504555462953;
                                                }
                                            } else {
                                                current_block = 8464383504555462953;
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    let mut buff_iter: core::ffi::c_int =
                                                        0 as core::ffi::c_int;
                                                    let fresh3 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh3 as usize] = 5 as core::ffi::c_uchar;
                                                    let fresh4 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh4 as usize] = 1 as core::ffi::c_uchar;
                                                    let fresh5 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh5 as usize] = 0 as core::ffi::c_uchar;
                                                    if dns_len == 0 {
                                                        let fresh6 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh6 as usize] = (if v6 != 0 {
                                                            4 as core::ffi::c_int
                                                        } else {
                                                            1 as core::ffi::c_int
                                                        })
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            (ip.addr.v6).as_mut_ptr()
                                                                as *const core::ffi::c_void,
                                                            (if v6 != 0 {
                                                                16 as core::ffi::c_int
                                                            } else {
                                                                4 as core::ffi::c_int
                                                            })
                                                                as size_t,
                                                        );
                                                        buff_iter += if v6 != 0 {
                                                            16 as core::ffi::c_int
                                                        } else {
                                                            4 as core::ffi::c_int
                                                        };
                                                    } else {
                                                        let fresh7 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh7 as usize] =
                                                            3 as core::ffi::c_uchar;
                                                        let fresh8 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh8 as usize] = (dns_len
                                                            & 0xff as size_t)
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            dns_name as *const core::ffi::c_void,
                                                            dns_len,
                                                        );
                                                        buff_iter = (buff_iter as size_t)
                                                            .wrapping_add(dns_len)
                                                            as core::ffi::c_int
                                                            as core::ffi::c_int;
                                                    }
                                                    memcpy(
                                                        buff.as_mut_ptr().offset(buff_iter as isize)
                                                            as *mut core::ffi::c_void,
                                                        &mut port as *mut core::ffi::c_ushort
                                                            as *const core::ffi::c_void,
                                                        2 as size_t,
                                                    );
                                                    buff_iter += 2 as core::ffi::c_int;
                                                    if !(buff_iter
                                                        != write_n_bytes(
                                                            sock,
                                                            buff.as_mut_ptr()
                                                                as *mut core::ffi::c_char,
                                                            buff_iter as size_t,
                                                        ))
                                                    {
                                                        if !(4 as core::ffi::c_int
                                                            != read_n_bytes(
                                                                sock,
                                                                buff.as_mut_ptr()
                                                                    as *mut core::ffi::c_char,
                                                                4 as size_t,
                                                            ))
                                                        {
                                                            if !(buff
                                                                [0 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                != 5 as core::ffi::c_int
                                                                || buff
                                                                    [1 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                    != 0 as core::ffi::c_int)
                                                            {
                                                                match buff
                                                                    [3 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                {
                                                                    1 => {
                                                                        current_block =
                                                                            11457429562336091101;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    4 => {
                                                                        current_block =
                                                                            14275417720432513913;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    3 => {
                                                                        current_block =
                                                                            8167664295155409685;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    0 => {
                        current_block = 8457315219000651999;
                        match current_block {
                            8588843005822345763 => return SUCCESS as core::ffi::c_int,
                            14072441030219150333 => {
                                if v6 != 0 {
                                    proxychains_write_log(
                                        b"[proxychains] error: SOCKS4 doesn't support ipv6 addresses\n\0"
                                            as *const u8 as *const core::ffi::c_char
                                            as *mut core::ffi::c_char,
                                    );
                                } else {
                                    buff[0 as core::ffi::c_int as usize] = 4 as core::ffi::c_uchar;
                                    buff[1 as core::ffi::c_int as usize] = 1 as core::ffi::c_uchar;
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(2 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut port as *mut core::ffi::c_ushort
                                            as *const core::ffi::c_void,
                                        2 as size_t,
                                    );
                                    if dns_len != 0 {
                                        ip.addr.v4.octet[0 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[1 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[2 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[3 as core::ffi::c_int as usize] =
                                            1 as core::ffi::c_uchar;
                                    }
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(4 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut ip.addr.v4 as *mut ip_type4
                                            as *const core::ffi::c_void,
                                        4 as size_t,
                                    );
                                    len = ulen.wrapping_add(1 as size_t) as core::ffi::c_int;
                                    if len > 1 as core::ffi::c_int {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset(8 as core::ffi::c_int as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            user as *const core::ffi::c_void,
                                            len as size_t,
                                        );
                                    } else {
                                        buff[8 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                    }
                                    if dns_len != 0 {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset((8 as core::ffi::c_int + len) as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            dns_name as *const core::ffi::c_void,
                                            dns_len.wrapping_add(1 as size_t),
                                        );
                                        len = (len as size_t)
                                            .wrapping_add(dns_len.wrapping_add(1 as size_t))
                                            as core::ffi::c_int
                                            as core::ffi::c_int;
                                    }
                                    if !(len + 8 as core::ffi::c_int
                                        != write_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            (8 as core::ffi::c_int + len) as size_t,
                                        ))
                                    {
                                        if !(8 as core::ffi::c_int
                                            != read_n_bytes(
                                                sock,
                                                buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                8 as size_t,
                                            ))
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                || buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 90 as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                            return SUCCESS as core::ffi::c_int;
                                        }
                                    }
                                }
                            }
                            8457315219000651999 => {
                                if dns_len == 0 {
                                    if (inet_ntop(
                                        if v6 != 0 { AF_INET6 } else { AF_INET },
                                        (ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                                        ip_buf.as_mut_ptr(),
                                        ::core::mem::size_of::<[core::ffi::c_char; 46]>()
                                            as socklen_t,
                                    ))
                                    .is_null()
                                    {
                                        proxychains_write_log(
                                            b"[proxychains] error: ip address conversion failed\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char
                                                as *mut core::ffi::c_char,
                                        );
                                        current_block = 4787357585276075074;
                                    } else {
                                        dns_name = ip_buf.as_mut_ptr();
                                        current_block = 5783071609795492627;
                                    }
                                } else {
                                    current_block = 5783071609795492627;
                                }
                                match current_block {
                                    4787357585276075074 => {}
                                    _ => {
                                        let mut src: [core::ffi::c_char; 512] = [0; 512];
                                        let mut dst: [core::ffi::c_char; 2048] = [0; 2048];
                                        if ulen != 0 {
                                            snprintf(
                                                src.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 512]>()
                                                    as size_t,
                                                b"%s:%s\0" as *const u8 as *const core::ffi::c_char,
                                                user,
                                                pass,
                                            );
                                            encode_base_64(
                                                src.as_mut_ptr(),
                                                dst.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 2048]>()
                                                    as core::ffi::c_int,
                                            );
                                        } else {
                                            dst[0 as core::ffi::c_int as usize] =
                                                0 as core::ffi::c_char;
                                        }
                                        let mut hs_port: uint16_t = ntohs(port as uint16_t);
                                        len = snprintf(
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            ::core::mem::size_of::<[core::ffi::c_uchar; 1024]>()
                                                as size_t,
                                            b"CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            if ulen != 0 {
                                                b"Proxy-Authorization: Basic \0" as *const u8
                                                    as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                            dst.as_mut_ptr(),
                                            if ulen != 0 {
                                                b"\r\n\0" as *const u8 as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                        );
                                        if !(len < 0 as core::ffi::c_int
                                            || len as ssize_t
                                                != send(
                                                    sock,
                                                    buff.as_mut_ptr() as *const core::ffi::c_void,
                                                    len as size_t,
                                                    0 as core::ffi::c_int,
                                                ))
                                        {
                                            len = 0 as core::ffi::c_int;
                                            loop {
                                                if !(len < BUFF_SIZE) {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                                if !(1 as core::ffi::c_int
                                                    == read_n_bytes(
                                                        sock,
                                                        buff.as_mut_ptr().offset(len as isize)
                                                            as *mut core::ffi::c_char,
                                                        1 as size_t,
                                                    ))
                                                {
                                                    current_block = 4787357585276075074;
                                                    break;
                                                }
                                                len += 1;
                                                if len > 4 as core::ffi::c_int
                                                    && buff[(len - 1 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 2 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                    && buff[(len - 3 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 4 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    if len == BUFF_SIZE
                                                        || !(buff[9 as core::ffi::c_int as usize]
                                                            as core::ffi::c_int
                                                            == '2' as i32
                                                            && buff[10 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32
                                                            && buff[11 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32)
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    return SUCCESS as core::ffi::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                let mut n_methods: core::ffi::c_int = if ulen != 0 {
                                    2 as core::ffi::c_int
                                } else {
                                    1 as core::ffi::c_int
                                };
                                buff[0 as core::ffi::c_int as usize] = 5 as core::ffi::c_uchar;
                                buff[1 as core::ffi::c_int as usize] =
                                    n_methods as core::ffi::c_uchar;
                                buff[2 as core::ffi::c_int as usize] = 0 as core::ffi::c_uchar;
                                if ulen != 0 {
                                    buff[3 as core::ffi::c_int as usize] = 2 as core::ffi::c_uchar;
                                }
                                if !(2 as core::ffi::c_int + n_methods
                                    != write_n_bytes(
                                        sock,
                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                        (2 as core::ffi::c_int + n_methods) as size_t,
                                    ))
                                {
                                    if !(2 as core::ffi::c_int
                                        != read_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            2 as size_t,
                                        ))
                                    {
                                        if buff[0 as core::ffi::c_int as usize] as core::ffi::c_int
                                            != 5 as core::ffi::c_int
                                            || buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 2 as core::ffi::c_int
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 5 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 0xff as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                        } else {
                                            if buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 2 as core::ffi::c_int
                                            {
                                                let mut in_0: [core::ffi::c_char; 2] = [0; 2];
                                                let mut out: [core::ffi::c_char; 515] = [0; 515];
                                                let mut cur: *mut core::ffi::c_char =
                                                    out.as_mut_ptr();
                                                let mut c: size_t = 0;
                                                let fresh0 = cur;
                                                cur = cur.offset(1);
                                                *fresh0 = 1 as core::ffi::c_char;
                                                c = ulen & 0xff as size_t;
                                                let fresh1 = cur;
                                                cur = cur.offset(1);
                                                *fresh1 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    user as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                c = passlen & 0xff as size_t;
                                                let fresh2 = cur;
                                                cur = cur.offset(1);
                                                *fresh2 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    pass as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                if cur.offset_from(out.as_mut_ptr())
                                                    as core::ffi::c_long
                                                    != write_n_bytes(
                                                        sock,
                                                        out.as_mut_ptr(),
                                                        cur.offset_from(out.as_mut_ptr())
                                                            as core::ffi::c_long
                                                            as size_t,
                                                    )
                                                        as core::ffi::c_long
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if 2 as core::ffi::c_int
                                                    != read_n_bytes(
                                                        sock,
                                                        in_0.as_mut_ptr(),
                                                        2 as size_t,
                                                    )
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if !(in_0[0 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 5 as core::ffi::c_int
                                                    || in_0[0 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        == 1 as core::ffi::c_int)
                                                {
                                                    current_block = 4787357585276075074;
                                                } else {
                                                    if in_0[1 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        != 0 as core::ffi::c_int
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    current_block = 8464383504555462953;
                                                }
                                            } else {
                                                current_block = 8464383504555462953;
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    let mut buff_iter: core::ffi::c_int =
                                                        0 as core::ffi::c_int;
                                                    let fresh3 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh3 as usize] = 5 as core::ffi::c_uchar;
                                                    let fresh4 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh4 as usize] = 1 as core::ffi::c_uchar;
                                                    let fresh5 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh5 as usize] = 0 as core::ffi::c_uchar;
                                                    if dns_len == 0 {
                                                        let fresh6 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh6 as usize] = (if v6 != 0 {
                                                            4 as core::ffi::c_int
                                                        } else {
                                                            1 as core::ffi::c_int
                                                        })
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            (ip.addr.v6).as_mut_ptr()
                                                                as *const core::ffi::c_void,
                                                            (if v6 != 0 {
                                                                16 as core::ffi::c_int
                                                            } else {
                                                                4 as core::ffi::c_int
                                                            })
                                                                as size_t,
                                                        );
                                                        buff_iter += if v6 != 0 {
                                                            16 as core::ffi::c_int
                                                        } else {
                                                            4 as core::ffi::c_int
                                                        };
                                                    } else {
                                                        let fresh7 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh7 as usize] =
                                                            3 as core::ffi::c_uchar;
                                                        let fresh8 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh8 as usize] = (dns_len
                                                            & 0xff as size_t)
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            dns_name as *const core::ffi::c_void,
                                                            dns_len,
                                                        );
                                                        buff_iter = (buff_iter as size_t)
                                                            .wrapping_add(dns_len)
                                                            as core::ffi::c_int
                                                            as core::ffi::c_int;
                                                    }
                                                    memcpy(
                                                        buff.as_mut_ptr().offset(buff_iter as isize)
                                                            as *mut core::ffi::c_void,
                                                        &mut port as *mut core::ffi::c_ushort
                                                            as *const core::ffi::c_void,
                                                        2 as size_t,
                                                    );
                                                    buff_iter += 2 as core::ffi::c_int;
                                                    if !(buff_iter
                                                        != write_n_bytes(
                                                            sock,
                                                            buff.as_mut_ptr()
                                                                as *mut core::ffi::c_char,
                                                            buff_iter as size_t,
                                                        ))
                                                    {
                                                        if !(4 as core::ffi::c_int
                                                            != read_n_bytes(
                                                                sock,
                                                                buff.as_mut_ptr()
                                                                    as *mut core::ffi::c_char,
                                                                4 as size_t,
                                                            ))
                                                        {
                                                            if !(buff
                                                                [0 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                != 5 as core::ffi::c_int
                                                                || buff
                                                                    [1 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                    != 0 as core::ffi::c_int)
                                                            {
                                                                match buff
                                                                    [3 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                {
                                                                    1 => {
                                                                        current_block =
                                                                            11457429562336091101;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    4 => {
                                                                        current_block =
                                                                            14275417720432513913;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    3 => {
                                                                        current_block =
                                                                            8167664295155409685;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    1 => {
                        current_block = 14072441030219150333;
                        match current_block {
                            8588843005822345763 => return SUCCESS as core::ffi::c_int,
                            14072441030219150333 => {
                                if v6 != 0 {
                                    proxychains_write_log(
                                        b"[proxychains] error: SOCKS4 doesn't support ipv6 addresses\n\0"
                                            as *const u8 as *const core::ffi::c_char
                                            as *mut core::ffi::c_char,
                                    );
                                } else {
                                    buff[0 as core::ffi::c_int as usize] = 4 as core::ffi::c_uchar;
                                    buff[1 as core::ffi::c_int as usize] = 1 as core::ffi::c_uchar;
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(2 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut port as *mut core::ffi::c_ushort
                                            as *const core::ffi::c_void,
                                        2 as size_t,
                                    );
                                    if dns_len != 0 {
                                        ip.addr.v4.octet[0 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[1 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[2 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[3 as core::ffi::c_int as usize] =
                                            1 as core::ffi::c_uchar;
                                    }
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(4 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut ip.addr.v4 as *mut ip_type4
                                            as *const core::ffi::c_void,
                                        4 as size_t,
                                    );
                                    len = ulen.wrapping_add(1 as size_t) as core::ffi::c_int;
                                    if len > 1 as core::ffi::c_int {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset(8 as core::ffi::c_int as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            user as *const core::ffi::c_void,
                                            len as size_t,
                                        );
                                    } else {
                                        buff[8 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                    }
                                    if dns_len != 0 {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset((8 as core::ffi::c_int + len) as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            dns_name as *const core::ffi::c_void,
                                            dns_len.wrapping_add(1 as size_t),
                                        );
                                        len = (len as size_t)
                                            .wrapping_add(dns_len.wrapping_add(1 as size_t))
                                            as core::ffi::c_int
                                            as core::ffi::c_int;
                                    }
                                    if !(len + 8 as core::ffi::c_int
                                        != write_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            (8 as core::ffi::c_int + len) as size_t,
                                        ))
                                    {
                                        if !(8 as core::ffi::c_int
                                            != read_n_bytes(
                                                sock,
                                                buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                8 as size_t,
                                            ))
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                || buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 90 as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                            return SUCCESS as core::ffi::c_int;
                                        }
                                    }
                                }
                            }
                            8457315219000651999 => {
                                if dns_len == 0 {
                                    if (inet_ntop(
                                        if v6 != 0 { AF_INET6 } else { AF_INET },
                                        (ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                                        ip_buf.as_mut_ptr(),
                                        ::core::mem::size_of::<[core::ffi::c_char; 46]>()
                                            as socklen_t,
                                    ))
                                    .is_null()
                                    {
                                        proxychains_write_log(
                                            b"[proxychains] error: ip address conversion failed\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char
                                                as *mut core::ffi::c_char,
                                        );
                                        current_block = 4787357585276075074;
                                    } else {
                                        dns_name = ip_buf.as_mut_ptr();
                                        current_block = 5783071609795492627;
                                    }
                                } else {
                                    current_block = 5783071609795492627;
                                }
                                match current_block {
                                    4787357585276075074 => {}
                                    _ => {
                                        let mut src: [core::ffi::c_char; 512] = [0; 512];
                                        let mut dst: [core::ffi::c_char; 2048] = [0; 2048];
                                        if ulen != 0 {
                                            snprintf(
                                                src.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 512]>()
                                                    as size_t,
                                                b"%s:%s\0" as *const u8 as *const core::ffi::c_char,
                                                user,
                                                pass,
                                            );
                                            encode_base_64(
                                                src.as_mut_ptr(),
                                                dst.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 2048]>()
                                                    as core::ffi::c_int,
                                            );
                                        } else {
                                            dst[0 as core::ffi::c_int as usize] =
                                                0 as core::ffi::c_char;
                                        }
                                        let mut hs_port: uint16_t = ntohs(port as uint16_t);
                                        len = snprintf(
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            ::core::mem::size_of::<[core::ffi::c_uchar; 1024]>()
                                                as size_t,
                                            b"CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            if ulen != 0 {
                                                b"Proxy-Authorization: Basic \0" as *const u8
                                                    as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                            dst.as_mut_ptr(),
                                            if ulen != 0 {
                                                b"\r\n\0" as *const u8 as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                        );
                                        if !(len < 0 as core::ffi::c_int
                                            || len as ssize_t
                                                != send(
                                                    sock,
                                                    buff.as_mut_ptr() as *const core::ffi::c_void,
                                                    len as size_t,
                                                    0 as core::ffi::c_int,
                                                ))
                                        {
                                            len = 0 as core::ffi::c_int;
                                            loop {
                                                if !(len < BUFF_SIZE) {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                                if !(1 as core::ffi::c_int
                                                    == read_n_bytes(
                                                        sock,
                                                        buff.as_mut_ptr().offset(len as isize)
                                                            as *mut core::ffi::c_char,
                                                        1 as size_t,
                                                    ))
                                                {
                                                    current_block = 4787357585276075074;
                                                    break;
                                                }
                                                len += 1;
                                                if len > 4 as core::ffi::c_int
                                                    && buff[(len - 1 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 2 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                    && buff[(len - 3 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 4 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    if len == BUFF_SIZE
                                                        || !(buff[9 as core::ffi::c_int as usize]
                                                            as core::ffi::c_int
                                                            == '2' as i32
                                                            && buff[10 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32
                                                            && buff[11 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32)
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    return SUCCESS as core::ffi::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                let mut n_methods: core::ffi::c_int = if ulen != 0 {
                                    2 as core::ffi::c_int
                                } else {
                                    1 as core::ffi::c_int
                                };
                                buff[0 as core::ffi::c_int as usize] = 5 as core::ffi::c_uchar;
                                buff[1 as core::ffi::c_int as usize] =
                                    n_methods as core::ffi::c_uchar;
                                buff[2 as core::ffi::c_int as usize] = 0 as core::ffi::c_uchar;
                                if ulen != 0 {
                                    buff[3 as core::ffi::c_int as usize] = 2 as core::ffi::c_uchar;
                                }
                                if !(2 as core::ffi::c_int + n_methods
                                    != write_n_bytes(
                                        sock,
                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                        (2 as core::ffi::c_int + n_methods) as size_t,
                                    ))
                                {
                                    if !(2 as core::ffi::c_int
                                        != read_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            2 as size_t,
                                        ))
                                    {
                                        if buff[0 as core::ffi::c_int as usize] as core::ffi::c_int
                                            != 5 as core::ffi::c_int
                                            || buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 2 as core::ffi::c_int
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 5 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 0xff as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                        } else {
                                            if buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 2 as core::ffi::c_int
                                            {
                                                let mut in_0: [core::ffi::c_char; 2] = [0; 2];
                                                let mut out: [core::ffi::c_char; 515] = [0; 515];
                                                let mut cur: *mut core::ffi::c_char =
                                                    out.as_mut_ptr();
                                                let mut c: size_t = 0;
                                                let fresh0 = cur;
                                                cur = cur.offset(1);
                                                *fresh0 = 1 as core::ffi::c_char;
                                                c = ulen & 0xff as size_t;
                                                let fresh1 = cur;
                                                cur = cur.offset(1);
                                                *fresh1 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    user as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                c = passlen & 0xff as size_t;
                                                let fresh2 = cur;
                                                cur = cur.offset(1);
                                                *fresh2 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    pass as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                if cur.offset_from(out.as_mut_ptr())
                                                    as core::ffi::c_long
                                                    != write_n_bytes(
                                                        sock,
                                                        out.as_mut_ptr(),
                                                        cur.offset_from(out.as_mut_ptr())
                                                            as core::ffi::c_long
                                                            as size_t,
                                                    )
                                                        as core::ffi::c_long
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if 2 as core::ffi::c_int
                                                    != read_n_bytes(
                                                        sock,
                                                        in_0.as_mut_ptr(),
                                                        2 as size_t,
                                                    )
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if !(in_0[0 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 5 as core::ffi::c_int
                                                    || in_0[0 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        == 1 as core::ffi::c_int)
                                                {
                                                    current_block = 4787357585276075074;
                                                } else {
                                                    if in_0[1 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        != 0 as core::ffi::c_int
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    current_block = 8464383504555462953;
                                                }
                                            } else {
                                                current_block = 8464383504555462953;
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    let mut buff_iter: core::ffi::c_int =
                                                        0 as core::ffi::c_int;
                                                    let fresh3 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh3 as usize] = 5 as core::ffi::c_uchar;
                                                    let fresh4 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh4 as usize] = 1 as core::ffi::c_uchar;
                                                    let fresh5 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh5 as usize] = 0 as core::ffi::c_uchar;
                                                    if dns_len == 0 {
                                                        let fresh6 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh6 as usize] = (if v6 != 0 {
                                                            4 as core::ffi::c_int
                                                        } else {
                                                            1 as core::ffi::c_int
                                                        })
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            (ip.addr.v6).as_mut_ptr()
                                                                as *const core::ffi::c_void,
                                                            (if v6 != 0 {
                                                                16 as core::ffi::c_int
                                                            } else {
                                                                4 as core::ffi::c_int
                                                            })
                                                                as size_t,
                                                        );
                                                        buff_iter += if v6 != 0 {
                                                            16 as core::ffi::c_int
                                                        } else {
                                                            4 as core::ffi::c_int
                                                        };
                                                    } else {
                                                        let fresh7 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh7 as usize] =
                                                            3 as core::ffi::c_uchar;
                                                        let fresh8 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh8 as usize] = (dns_len
                                                            & 0xff as size_t)
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            dns_name as *const core::ffi::c_void,
                                                            dns_len,
                                                        );
                                                        buff_iter = (buff_iter as size_t)
                                                            .wrapping_add(dns_len)
                                                            as core::ffi::c_int
                                                            as core::ffi::c_int;
                                                    }
                                                    memcpy(
                                                        buff.as_mut_ptr().offset(buff_iter as isize)
                                                            as *mut core::ffi::c_void,
                                                        &mut port as *mut core::ffi::c_ushort
                                                            as *const core::ffi::c_void,
                                                        2 as size_t,
                                                    );
                                                    buff_iter += 2 as core::ffi::c_int;
                                                    if !(buff_iter
                                                        != write_n_bytes(
                                                            sock,
                                                            buff.as_mut_ptr()
                                                                as *mut core::ffi::c_char,
                                                            buff_iter as size_t,
                                                        ))
                                                    {
                                                        if !(4 as core::ffi::c_int
                                                            != read_n_bytes(
                                                                sock,
                                                                buff.as_mut_ptr()
                                                                    as *mut core::ffi::c_char,
                                                                4 as size_t,
                                                            ))
                                                        {
                                                            if !(buff
                                                                [0 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                != 5 as core::ffi::c_int
                                                                || buff
                                                                    [1 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                    != 0 as core::ffi::c_int)
                                                            {
                                                                match buff
                                                                    [3 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                {
                                                                    1 => {
                                                                        current_block =
                                                                            11457429562336091101;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    4 => {
                                                                        current_block =
                                                                            14275417720432513913;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    3 => {
                                                                        current_block =
                                                                            8167664295155409685;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    2 => {
                        current_block = 17728966195399430138;
                        match current_block {
                            8588843005822345763 => return SUCCESS as core::ffi::c_int,
                            14072441030219150333 => {
                                if v6 != 0 {
                                    proxychains_write_log(
                                        b"[proxychains] error: SOCKS4 doesn't support ipv6 addresses\n\0"
                                            as *const u8 as *const core::ffi::c_char
                                            as *mut core::ffi::c_char,
                                    );
                                } else {
                                    buff[0 as core::ffi::c_int as usize] = 4 as core::ffi::c_uchar;
                                    buff[1 as core::ffi::c_int as usize] = 1 as core::ffi::c_uchar;
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(2 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut port as *mut core::ffi::c_ushort
                                            as *const core::ffi::c_void,
                                        2 as size_t,
                                    );
                                    if dns_len != 0 {
                                        ip.addr.v4.octet[0 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[1 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[2 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                        ip.addr.v4.octet[3 as core::ffi::c_int as usize] =
                                            1 as core::ffi::c_uchar;
                                    }
                                    memcpy(
                                        &mut *buff
                                            .as_mut_ptr()
                                            .offset(4 as core::ffi::c_int as isize)
                                            as *mut core::ffi::c_uchar
                                            as *mut core::ffi::c_void,
                                        &mut ip.addr.v4 as *mut ip_type4
                                            as *const core::ffi::c_void,
                                        4 as size_t,
                                    );
                                    len = ulen.wrapping_add(1 as size_t) as core::ffi::c_int;
                                    if len > 1 as core::ffi::c_int {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset(8 as core::ffi::c_int as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            user as *const core::ffi::c_void,
                                            len as size_t,
                                        );
                                    } else {
                                        buff[8 as core::ffi::c_int as usize] =
                                            0 as core::ffi::c_uchar;
                                    }
                                    if dns_len != 0 {
                                        memcpy(
                                            &mut *buff
                                                .as_mut_ptr()
                                                .offset((8 as core::ffi::c_int + len) as isize)
                                                as *mut core::ffi::c_uchar
                                                as *mut core::ffi::c_void,
                                            dns_name as *const core::ffi::c_void,
                                            dns_len.wrapping_add(1 as size_t),
                                        );
                                        len = (len as size_t)
                                            .wrapping_add(dns_len.wrapping_add(1 as size_t))
                                            as core::ffi::c_int
                                            as core::ffi::c_int;
                                    }
                                    if !(len + 8 as core::ffi::c_int
                                        != write_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            (8 as core::ffi::c_int + len) as size_t,
                                        ))
                                    {
                                        if !(8 as core::ffi::c_int
                                            != read_n_bytes(
                                                sock,
                                                buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                8 as size_t,
                                            ))
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                || buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 90 as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                            return SUCCESS as core::ffi::c_int;
                                        }
                                    }
                                }
                            }
                            8457315219000651999 => {
                                if dns_len == 0 {
                                    if (inet_ntop(
                                        if v6 != 0 { AF_INET6 } else { AF_INET },
                                        (ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                                        ip_buf.as_mut_ptr(),
                                        ::core::mem::size_of::<[core::ffi::c_char; 46]>()
                                            as socklen_t,
                                    ))
                                    .is_null()
                                    {
                                        proxychains_write_log(
                                            b"[proxychains] error: ip address conversion failed\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char
                                                as *mut core::ffi::c_char,
                                        );
                                        current_block = 4787357585276075074;
                                    } else {
                                        dns_name = ip_buf.as_mut_ptr();
                                        current_block = 5783071609795492627;
                                    }
                                } else {
                                    current_block = 5783071609795492627;
                                }
                                match current_block {
                                    4787357585276075074 => {}
                                    _ => {
                                        let mut src: [core::ffi::c_char; 512] = [0; 512];
                                        let mut dst: [core::ffi::c_char; 2048] = [0; 2048];
                                        if ulen != 0 {
                                            snprintf(
                                                src.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 512]>()
                                                    as size_t,
                                                b"%s:%s\0" as *const u8 as *const core::ffi::c_char,
                                                user,
                                                pass,
                                            );
                                            encode_base_64(
                                                src.as_mut_ptr(),
                                                dst.as_mut_ptr(),
                                                ::core::mem::size_of::<[core::ffi::c_char; 2048]>()
                                                    as core::ffi::c_int,
                                            );
                                        } else {
                                            dst[0 as core::ffi::c_int as usize] =
                                                0 as core::ffi::c_char;
                                        }
                                        let mut hs_port: uint16_t = ntohs(port as uint16_t);
                                        len = snprintf(
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            ::core::mem::size_of::<[core::ffi::c_uchar; 1024]>()
                                                as size_t,
                                            b"CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n\0"
                                                as *const u8
                                                as *const core::ffi::c_char,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            dns_name,
                                            hs_port as core::ffi::c_int,
                                            if ulen != 0 {
                                                b"Proxy-Authorization: Basic \0" as *const u8
                                                    as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                            dst.as_mut_ptr(),
                                            if ulen != 0 {
                                                b"\r\n\0" as *const u8 as *const core::ffi::c_char
                                            } else {
                                                dst.as_mut_ptr() as *const core::ffi::c_char
                                            },
                                        );
                                        if !(len < 0 as core::ffi::c_int
                                            || len as ssize_t
                                                != send(
                                                    sock,
                                                    buff.as_mut_ptr() as *const core::ffi::c_void,
                                                    len as size_t,
                                                    0 as core::ffi::c_int,
                                                ))
                                        {
                                            len = 0 as core::ffi::c_int;
                                            loop {
                                                if !(len < BUFF_SIZE) {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                                if !(1 as core::ffi::c_int
                                                    == read_n_bytes(
                                                        sock,
                                                        buff.as_mut_ptr().offset(len as isize)
                                                            as *mut core::ffi::c_char,
                                                        1 as size_t,
                                                    ))
                                                {
                                                    current_block = 4787357585276075074;
                                                    break;
                                                }
                                                len += 1;
                                                if len > 4 as core::ffi::c_int
                                                    && buff[(len - 1 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 2 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                    && buff[(len - 3 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\n' as i32
                                                    && buff[(len - 4 as core::ffi::c_int) as usize]
                                                        as core::ffi::c_int
                                                        == '\r' as i32
                                                {
                                                    current_block = 8704759739624374314;
                                                    break;
                                                }
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    if len == BUFF_SIZE
                                                        || !(buff[9 as core::ffi::c_int as usize]
                                                            as core::ffi::c_int
                                                            == '2' as i32
                                                            && buff[10 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32
                                                            && buff[11 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                == '0' as i32)
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    return SUCCESS as core::ffi::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                let mut n_methods: core::ffi::c_int = if ulen != 0 {
                                    2 as core::ffi::c_int
                                } else {
                                    1 as core::ffi::c_int
                                };
                                buff[0 as core::ffi::c_int as usize] = 5 as core::ffi::c_uchar;
                                buff[1 as core::ffi::c_int as usize] =
                                    n_methods as core::ffi::c_uchar;
                                buff[2 as core::ffi::c_int as usize] = 0 as core::ffi::c_uchar;
                                if ulen != 0 {
                                    buff[3 as core::ffi::c_int as usize] = 2 as core::ffi::c_uchar;
                                }
                                if !(2 as core::ffi::c_int + n_methods
                                    != write_n_bytes(
                                        sock,
                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                        (2 as core::ffi::c_int + n_methods) as size_t,
                                    ))
                                {
                                    if !(2 as core::ffi::c_int
                                        != read_n_bytes(
                                            sock,
                                            buff.as_mut_ptr() as *mut core::ffi::c_char,
                                            2 as size_t,
                                        ))
                                    {
                                        if buff[0 as core::ffi::c_int as usize] as core::ffi::c_int
                                            != 5 as core::ffi::c_int
                                            || buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                != 0 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    != 2 as core::ffi::c_int
                                        {
                                            if buff[0 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 5 as core::ffi::c_int
                                                && buff[1 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 0xff as core::ffi::c_int
                                            {
                                                return BLOCKED as core::ffi::c_int;
                                            }
                                        } else {
                                            if buff[1 as core::ffi::c_int as usize]
                                                as core::ffi::c_int
                                                == 2 as core::ffi::c_int
                                            {
                                                let mut in_0: [core::ffi::c_char; 2] = [0; 2];
                                                let mut out: [core::ffi::c_char; 515] = [0; 515];
                                                let mut cur: *mut core::ffi::c_char =
                                                    out.as_mut_ptr();
                                                let mut c: size_t = 0;
                                                let fresh0 = cur;
                                                cur = cur.offset(1);
                                                *fresh0 = 1 as core::ffi::c_char;
                                                c = ulen & 0xff as size_t;
                                                let fresh1 = cur;
                                                cur = cur.offset(1);
                                                *fresh1 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    user as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                c = passlen & 0xff as size_t;
                                                let fresh2 = cur;
                                                cur = cur.offset(1);
                                                *fresh2 = c as core::ffi::c_char;
                                                memcpy(
                                                    cur as *mut core::ffi::c_void,
                                                    pass as *const core::ffi::c_void,
                                                    c,
                                                );
                                                cur = cur.offset(c as isize);
                                                if cur.offset_from(out.as_mut_ptr())
                                                    as core::ffi::c_long
                                                    != write_n_bytes(
                                                        sock,
                                                        out.as_mut_ptr(),
                                                        cur.offset_from(out.as_mut_ptr())
                                                            as core::ffi::c_long
                                                            as size_t,
                                                    )
                                                        as core::ffi::c_long
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if 2 as core::ffi::c_int
                                                    != read_n_bytes(
                                                        sock,
                                                        in_0.as_mut_ptr(),
                                                        2 as size_t,
                                                    )
                                                {
                                                    current_block = 4787357585276075074;
                                                } else if !(in_0[0 as core::ffi::c_int as usize]
                                                    as core::ffi::c_int
                                                    == 5 as core::ffi::c_int
                                                    || in_0[0 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        == 1 as core::ffi::c_int)
                                                {
                                                    current_block = 4787357585276075074;
                                                } else {
                                                    if in_0[1 as core::ffi::c_int as usize]
                                                        as core::ffi::c_int
                                                        != 0 as core::ffi::c_int
                                                    {
                                                        return BLOCKED as core::ffi::c_int;
                                                    }
                                                    current_block = 8464383504555462953;
                                                }
                                            } else {
                                                current_block = 8464383504555462953;
                                            }
                                            match current_block {
                                                4787357585276075074 => {}
                                                _ => {
                                                    let mut buff_iter: core::ffi::c_int =
                                                        0 as core::ffi::c_int;
                                                    let fresh3 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh3 as usize] = 5 as core::ffi::c_uchar;
                                                    let fresh4 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh4 as usize] = 1 as core::ffi::c_uchar;
                                                    let fresh5 = buff_iter;
                                                    buff_iter = buff_iter + 1;
                                                    buff[fresh5 as usize] = 0 as core::ffi::c_uchar;
                                                    if dns_len == 0 {
                                                        let fresh6 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh6 as usize] = (if v6 != 0 {
                                                            4 as core::ffi::c_int
                                                        } else {
                                                            1 as core::ffi::c_int
                                                        })
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            (ip.addr.v6).as_mut_ptr()
                                                                as *const core::ffi::c_void,
                                                            (if v6 != 0 {
                                                                16 as core::ffi::c_int
                                                            } else {
                                                                4 as core::ffi::c_int
                                                            })
                                                                as size_t,
                                                        );
                                                        buff_iter += if v6 != 0 {
                                                            16 as core::ffi::c_int
                                                        } else {
                                                            4 as core::ffi::c_int
                                                        };
                                                    } else {
                                                        let fresh7 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh7 as usize] =
                                                            3 as core::ffi::c_uchar;
                                                        let fresh8 = buff_iter;
                                                        buff_iter = buff_iter + 1;
                                                        buff[fresh8 as usize] = (dns_len
                                                            & 0xff as size_t)
                                                            as core::ffi::c_uchar;
                                                        memcpy(
                                                            buff.as_mut_ptr()
                                                                .offset(buff_iter as isize)
                                                                as *mut core::ffi::c_void,
                                                            dns_name as *const core::ffi::c_void,
                                                            dns_len,
                                                        );
                                                        buff_iter = (buff_iter as size_t)
                                                            .wrapping_add(dns_len)
                                                            as core::ffi::c_int
                                                            as core::ffi::c_int;
                                                    }
                                                    memcpy(
                                                        buff.as_mut_ptr().offset(buff_iter as isize)
                                                            as *mut core::ffi::c_void,
                                                        &mut port as *mut core::ffi::c_ushort
                                                            as *const core::ffi::c_void,
                                                        2 as size_t,
                                                    );
                                                    buff_iter += 2 as core::ffi::c_int;
                                                    if !(buff_iter
                                                        != write_n_bytes(
                                                            sock,
                                                            buff.as_mut_ptr()
                                                                as *mut core::ffi::c_char,
                                                            buff_iter as size_t,
                                                        ))
                                                    {
                                                        if !(4 as core::ffi::c_int
                                                            != read_n_bytes(
                                                                sock,
                                                                buff.as_mut_ptr()
                                                                    as *mut core::ffi::c_char,
                                                                4 as size_t,
                                                            ))
                                                        {
                                                            if !(buff
                                                                [0 as core::ffi::c_int as usize]
                                                                as core::ffi::c_int
                                                                != 5 as core::ffi::c_int
                                                                || buff
                                                                    [1 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                    != 0 as core::ffi::c_int)
                                                            {
                                                                match buff
                                                                    [3 as core::ffi::c_int as usize]
                                                                    as core::ffi::c_int
                                                                {
                                                                    1 => {
                                                                        current_block =
                                                                            11457429562336091101;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    4 => {
                                                                        current_block =
                                                                            14275417720432513913;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    3 => {
                                                                        current_block =
                                                                            8167664295155409685;
                                                                        match current_block {
                                                                            14275417720432513913 => {
                                                                                len = 16 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            11457429562336091101 => {
                                                                                len = 4 as core::ffi::c_int;
                                                                                current_block = 4899250571165509867;
                                                                            }
                                                                            _ => {
                                                                                len = 0 as core::ffi::c_int;
                                                                                if 1 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        &mut len as *mut core::ffi::c_int as *mut core::ffi::c_char,
                                                                                        1 as size_t,
                                                                                    )
                                                                                {
                                                                                    current_block = 4787357585276075074;
                                                                                } else {
                                                                                    current_block = 4899250571165509867;
                                                                                }
                                                                            }
                                                                        }
                                                                        match current_block {
                                                                            4787357585276075074 => {}
                                                                            _ => {
                                                                                if !(len + 2 as core::ffi::c_int
                                                                                    != read_n_bytes(
                                                                                        sock,
                                                                                        buff.as_mut_ptr() as *mut core::ffi::c_char,
                                                                                        (len + 2 as core::ffi::c_int) as size_t,
                                                                                    ))
                                                                                {
                                                                                    return SUCCESS as core::ffi::c_int;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    return SOCKET_ERROR as core::ffi::c_int;
}
pub const DT: [core::ffi::c_char; 14] =
    unsafe { ::core::mem::transmute::<[u8; 14], [core::ffi::c_char; 14]>(*b"Dynamic chain\0") };
pub const ST: [core::ffi::c_char; 13] =
    unsafe { ::core::mem::transmute::<[u8; 13], [core::ffi::c_char; 13]>(*b"Strict chain\0") };
pub const RT: [core::ffi::c_char; 13] =
    unsafe { ::core::mem::transmute::<[u8; 13], [core::ffi::c_char; 13]>(*b"Random chain\0") };
pub const RRT: [core::ffi::c_char; 18] =
    unsafe { ::core::mem::transmute::<[u8; 18], [core::ffi::c_char; 18]>(*b"Round Robin chain\0") };
unsafe extern "C" fn start_chain(
    mut fd: *mut core::ffi::c_int,
    mut pd: *mut proxy_data,
    mut begin_mark: *mut core::ffi::c_char,
) -> core::ffi::c_int {
    let mut ip_buf: [core::ffi::c_char; 46] = [0; 46];
    let mut addr: sockaddr_in = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut addr6: sockaddr_in6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: CoreUnnamed {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    let mut v6: core::ffi::c_int = (*pd).ip.is_v6 as core::ffi::c_int;
    *fd = socket(
        if v6 != 0 { PF_INET6 } else { PF_INET },
        SOCK_STREAM as core::ffi::c_int,
        0 as core::ffi::c_int,
    );
    if !(*fd == -(1 as core::ffi::c_int)) {
        ip_buf = [0; 46];
        if !(inet_ntop(
            if v6 != 0 { AF_INET6 } else { AF_INET },
            ((*pd).ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
            ip_buf.as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 46]>() as socklen_t,
        ))
        .is_null()
        {
            proxychains_write_log(
                b"[proxychains] %s  ...  %s:%d \0" as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char,
                begin_mark,
                ip_buf.as_mut_ptr(),
                htons((*pd).port as uint16_t) as core::ffi::c_int,
            );
            (*pd).ps = PLAY_STATE;
            addr = {
                let mut init = sockaddr_in {
                    sin_family: AF_INET as sa_family_t,
                    sin_port: (*pd).port as in_port_t,
                    sin_addr: {
                        let mut init = in_addr {
                            s_addr: (*pd).ip.addr.v4.as_int,
                        };
                        init
                    },
                    sin_zero: [0; 8],
                };
                init
            };
            addr6 = {
                let mut init = sockaddr_in6 {
                    sin6_family: AF_INET6 as sa_family_t,
                    sin6_port: (*pd).port as in_port_t,
                    sin6_flowinfo: 0,
                    sin6_addr: in6_addr {
                        __in6_u: CoreUnnamed {
                            __u6_addr8: [0; 16],
                        },
                    },
                    sin6_scope_id: 0,
                };
                init
            };
            if v6 != 0 {
                memcpy(
                    &mut addr6.sin6_addr.__in6_u.__u6_addr8 as *mut [uint8_t; 16]
                        as *mut core::ffi::c_void,
                    ((*pd).ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                    16 as size_t,
                );
            }
            if crate::libproxychains::proxychains_verbose_debug != 0 {
                proxychains_write_log(
                    b"[proxychains-debug] start_chain: calling timed_connect fd=%d target=%s:%d\n\0"
                        as *const u8 as *const core::ffi::c_char
                        as *mut core::ffi::c_char,
                    *fd,
                    ip_buf.as_mut_ptr(),
                    htons((*pd).port as uint16_t) as core::ffi::c_int,
                );
            }
            if timed_connect(
                *fd,
                (if v6 != 0 {
                    &mut addr6 as *mut sockaddr_in6 as *mut core::ffi::c_void
                } else {
                    &mut addr as *mut sockaddr_in as *mut core::ffi::c_void
                }) as *mut sockaddr,
                (if v6 != 0 {
                    ::core::mem::size_of::<sockaddr_in6>() as usize
                } else {
                    ::core::mem::size_of::<sockaddr_in>() as usize
                }) as socklen_t,
            ) != 0
            {
                (*pd).ps = DOWN_STATE;
                if crate::libproxychains::proxychains_verbose_debug != 0 {
                    proxychains_write_log(
                        b"[proxychains-debug] start_chain: timed_connect failed fd=%d errno=%d\n\0"
                            as *const u8 as *const core::ffi::c_char
                            as *mut core::ffi::c_char,
                        *fd,
                        *__errno_location(),
                    );
                }
                proxychains_write_log(
                    b" ...  timeout\n\0" as *const u8 as *const core::ffi::c_char
                        as *mut core::ffi::c_char,
                );
            } else {
                (*pd).ps = BUSY_STATE;
                return SUCCESS as core::ffi::c_int;
            }
        }
    }
    if *fd != -(1 as core::ffi::c_int) {
        close(*fd);
        *fd = -(1 as core::ffi::c_int);
    }
    return SOCKET_ERROR as core::ffi::c_int;
}
unsafe extern "C" fn select_proxy(
    mut how: select_type,
    mut pd: *mut proxy_data,
    mut proxy_count: core::ffi::c_uint,
    mut offset: *mut core::ffi::c_uint,
) -> *mut proxy_data {
    let mut i: core::ffi::c_uint = 0 as core::ffi::c_uint;
    let mut k: core::ffi::c_uint = 0 as core::ffi::c_uint;
    if *offset >= proxy_count {
        return 0 as *mut proxy_data;
    }
    match how as core::ffi::c_uint {
        0 => loop {
            k = k.wrapping_add(1);
            i = (rand() as core::ffi::c_uint).wrapping_rem(proxy_count);
            if !((*pd.offset(i as isize)).ps as core::ffi::c_uint
                != PLAY_STATE as core::ffi::c_int as core::ffi::c_uint
                && k < proxy_count.wrapping_mul(100 as core::ffi::c_uint))
            {
                break;
            }
        },
        1 => {
            i = *offset;
            while i < proxy_count {
                if (*pd.offset(i as isize)).ps as core::ffi::c_uint
                    == PLAY_STATE as core::ffi::c_int as core::ffi::c_uint
                {
                    *offset = i;
                    break;
                } else {
                    i = i.wrapping_add(1);
                }
            }
        }
        _ => {}
    }
    if i >= proxy_count {
        i = 0 as core::ffi::c_uint;
    }
    return if (*pd.offset(i as isize)).ps as core::ffi::c_uint
        == PLAY_STATE as core::ffi::c_int as core::ffi::c_uint
    {
        &mut *pd.offset(i as isize) as *mut proxy_data
    } else {
        0 as *mut proxy_data
    };
}
unsafe extern "C" fn release_all(mut pd: *mut proxy_data, mut proxy_count: core::ffi::c_uint) {
    let mut i: core::ffi::c_uint = 0;
    i = 0 as core::ffi::c_uint;
    while i < proxy_count {
        (*pd.offset(i as isize)).ps = PLAY_STATE;
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn release_busy(mut pd: *mut proxy_data, mut proxy_count: core::ffi::c_uint) {
    let mut i: core::ffi::c_uint = 0;
    i = 0 as core::ffi::c_uint;
    while i < proxy_count {
        if (*pd.offset(i as isize)).ps as core::ffi::c_uint
            == BUSY_STATE as core::ffi::c_int as core::ffi::c_uint
        {
            (*pd.offset(i as isize)).ps = PLAY_STATE;
        }
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn calc_alive(
    mut pd: *mut proxy_data,
    mut proxy_count: core::ffi::c_uint,
) -> core::ffi::c_uint {
    let mut i: core::ffi::c_uint = 0;
    let mut alive_count: core::ffi::c_int = 0 as core::ffi::c_int;
    release_busy(pd, proxy_count);
    i = 0 as core::ffi::c_uint;
    while i < proxy_count {
        if (*pd.offset(i as isize)).ps as core::ffi::c_uint
            == PLAY_STATE as core::ffi::c_int as core::ffi::c_uint
        {
            alive_count += 1;
        }
        i = i.wrapping_add(1);
    }
    return alive_count as core::ffi::c_uint;
}
unsafe extern "C" fn chain_step(
    mut ns: *mut core::ffi::c_int,
    mut pfrom: *mut proxy_data,
    mut pto: *mut proxy_data,
) -> core::ffi::c_int {
    let mut current_block: u64;
    let mut retcode: core::ffi::c_int = -(1 as core::ffi::c_int);
    let mut hostname: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut errmsg: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut hostname_buf: [core::ffi::c_char; 256] = [0; 256];
    let mut ip_buf: [core::ffi::c_char; 46] = [0; 46];
    let mut v6: core::ffi::c_int = (*pto).ip.is_v6 as core::ffi::c_int;
    if v6 == 0
        && proxychains_resolver as core::ffi::c_uint
            >= DNSLF_RDNS_START as core::ffi::c_int as core::ffi::c_uint
        && (*pto).ip.addr.v4.octet[0 as core::ffi::c_int as usize] as core::ffi::c_uint
            == remote_dns_subnet
    {
        if rdns_get_host_for_ip((*pto).ip.addr.v4, hostname_buf.as_mut_ptr()) == 0 {
            current_block = 6899475132526888963;
        } else {
            hostname = hostname_buf.as_mut_ptr();
            current_block = 3512920355445576850;
        }
    } else {
        current_block = 6899475132526888963;
    }
    match current_block {
        6899475132526888963 => {
            if (inet_ntop(
                if v6 != 0 { AF_INET6 } else { AF_INET },
                ((*pto).ip.addr.v6).as_mut_ptr() as *const core::ffi::c_void,
                ip_buf.as_mut_ptr(),
                ::core::mem::size_of::<[core::ffi::c_char; 46]>() as socklen_t,
            ))
            .is_null()
            {
                (*pto).ps = DOWN_STATE;
                errmsg = b"<--ip conversion error!\n\0" as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char;
                retcode = SOCKET_ERROR as core::ffi::c_int;
                current_block = 15614789721076686620;
            } else {
                hostname = ip_buf.as_mut_ptr();
                current_block = 3512920355445576850;
            }
        }
        _ => {}
    }
    match current_block {
        3512920355445576850 => {
            proxychains_write_log(
                b" ...  %s:%d \0" as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char,
                hostname,
                htons((*pto).port as uint16_t) as core::ffi::c_int,
            );
            retcode = tunnel_to(
                *ns,
                (*pto).ip,
                (*pto).port,
                (*pfrom).pt,
                ((*pfrom).user).as_mut_ptr(),
                ((*pfrom).pass).as_mut_ptr(),
            );
            match retcode {
                0 => {
                    (*pto).ps = BUSY_STATE;
                    current_block = 15089075282327824602;
                }
                5 => {
                    (*pto).ps = BLOCKED_STATE;
                    errmsg = b"<--denied\n\0" as *const u8 as *const core::ffi::c_char
                        as *mut core::ffi::c_char;
                    current_block = 15614789721076686620;
                }
                2 => {
                    (*pto).ps = DOWN_STATE;
                    errmsg = b"<--socket error or timeout!\n\0" as *const u8
                        as *const core::ffi::c_char
                        as *mut core::ffi::c_char;
                    current_block = 15614789721076686620;
                }
                _ => {
                    current_block = 15089075282327824602;
                }
            }
            match current_block {
                15614789721076686620 => {}
                _ => return retcode,
            }
        }
        _ => {}
    }
    if !errmsg.is_null() {
        proxychains_write_log(errmsg);
    }
    if *ns != -(1 as core::ffi::c_int) {
        close(*ns);
    }
    *ns = -(1 as core::ffi::c_int);
    return retcode;
}
#[no_mangle]
pub unsafe extern "C" fn connect_proxy_chain(
    mut sock: core::ffi::c_int,
    mut target_ip: ip_type,
    mut target_port: core::ffi::c_ushort,
    mut pd: *mut proxy_data,
    mut proxy_count: core::ffi::c_uint,
    mut ct: chain_type,
    mut max_chain: core::ffi::c_uint,
) -> core::ffi::c_int {
    let mut current_block: u64;
    let mut p4: proxy_data = proxy_data {
        ip: ip_type {
            addr: CoreUnnamed1 {
                v4: ip_type4 { octet: [0; 4] },
            },
            is_v6: 0,
        },
        port: 0,
        pt: HTTP_TYPE,
        ps: PLAY_STATE,
        user: [0; 256],
        pass: [0; 256],
    };
    let mut p1: *mut proxy_data = 0 as *mut proxy_data;
    let mut p2: *mut proxy_data = 0 as *mut proxy_data;
    let mut p3: *mut proxy_data = 0 as *mut proxy_data;
    let mut ns: core::ffi::c_int = -(1 as core::ffi::c_int);
    let mut rc: core::ffi::c_int = -(1 as core::ffi::c_int);
    let mut offset: core::ffi::c_uint = 0 as core::ffi::c_uint;
    let mut alive_count: core::ffi::c_uint = 0 as core::ffi::c_uint;
    let mut curr_len: core::ffi::c_uint = 0 as core::ffi::c_uint;
    let mut looped: core::ffi::c_uint = 0 as core::ffi::c_uint;
    let mut rr_loop_max: core::ffi::c_uint = 14 as core::ffi::c_uint;
    p3 = &mut p4;
    '_again: loop {
        rc = -(1 as core::ffi::c_int);
        match ct as core::ffi::c_uint {
            0 => {
                alive_count = calc_alive(pd, proxy_count);
                offset = 0 as core::ffi::c_uint;
                loop {
                    p1 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                    if p1.is_null() {
                        current_block = 9883066750544168046;
                        break '_again;
                    }
                    if !(SUCCESS as core::ffi::c_int
                        != start_chain(&mut ns, p1, DT.as_ptr() as *mut core::ffi::c_char)
                        && offset < proxy_count)
                    {
                        break;
                    }
                }
                loop {
                    p2 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                    if p2.is_null() {
                        break;
                    }
                    if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p2) {
                        continue '_again;
                    }
                    p1 = p2;
                }
                (*p3).ip = target_ip;
                (*p3).port = target_port;
                if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p3) {
                    current_block = 16306980487779480232;
                    break;
                } else {
                    current_block = 3634396408142324656;
                    break;
                }
            }
            3 => {
                alive_count = calc_alive(pd, proxy_count);
                offset = proxychains_proxy_offset;
                if alive_count < max_chain {
                    current_block = 9883066750544168046;
                    break;
                }
                while rc != SUCCESS as core::ffi::c_int {
                    p1 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                    if p1.is_null() {
                        offset = 0 as core::ffi::c_uint;
                        looped = looped.wrapping_add(1);
                        if looped > rr_loop_max {
                            proxychains_proxy_offset = 0 as core::ffi::c_uint;
                            current_block = 9883066750544168046;
                            break '_again;
                        } else {
                            release_all(pd, proxy_count);
                            usleep((10000 as __useconds_t).wrapping_mul(looped as __useconds_t));
                        }
                    } else {
                        rc = start_chain(&mut ns, p1, RRT.as_ptr() as *mut core::ffi::c_char);
                    }
                }
                curr_len = 1 as core::ffi::c_uint;
                while curr_len < max_chain {
                    p2 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                    if p2.is_null() {
                        offset = 0 as core::ffi::c_uint;
                    } else {
                        if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p2) {
                            continue '_again;
                        }
                        p1 = p2;
                        curr_len = curr_len.wrapping_add(1);
                    }
                }
                (*p3).ip = target_ip;
                (*p3).port = target_port;
                proxychains_proxy_offset = offset.wrapping_add(1 as core::ffi::c_uint);
                if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p3) {
                    current_block = 16306980487779480232;
                    break;
                } else {
                    current_block = 3634396408142324656;
                    break;
                }
            }
            1 => {
                alive_count = calc_alive(pd, proxy_count);
                offset = 0 as core::ffi::c_uint;
                p1 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                if p1.is_null() {
                    current_block = 2220405792722996547;
                    break;
                } else {
                    current_block = 5372832139739605200;
                    break;
                }
            }
            2 => {
                alive_count = calc_alive(pd, proxy_count);
                if alive_count < max_chain {
                    current_block = 9883066750544168046;
                    break;
                }
                offset = 0 as core::ffi::c_uint;
                curr_len = offset;
                loop {
                    p1 = select_proxy(RANDOMLY, pd, proxy_count, &mut offset);
                    if p1.is_null() {
                        current_block = 9883066750544168046;
                        break '_again;
                    }
                    if !(SUCCESS as core::ffi::c_int
                        != start_chain(&mut ns, p1, RT.as_ptr() as *mut core::ffi::c_char)
                        && offset < max_chain)
                    {
                        break;
                    }
                }
                loop {
                    curr_len = curr_len.wrapping_add(1);
                    if !(curr_len < max_chain) {
                        break;
                    }
                    p2 = select_proxy(RANDOMLY, pd, proxy_count, &mut offset);
                    if p2.is_null() {
                        current_block = 9883066750544168046;
                        break '_again;
                    }
                    if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p2) {
                        continue '_again;
                    }
                    p1 = p2;
                }
                (*p3).ip = target_ip;
                (*p3).port = target_port;
                if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p3) {
                    current_block = 16306980487779480232;
                    break;
                } else {
                    current_block = 3634396408142324656;
                    break;
                }
            }
            _ => {
                current_block = 3634396408142324656;
                break;
            }
        }
    }
    match current_block {
        5372832139739605200 => {
            if SUCCESS as core::ffi::c_int
                != start_chain(&mut ns, p1, ST.as_ptr() as *mut core::ffi::c_char)
            {
                current_block = 2220405792722996547;
            } else {
                loop {
                    if !(offset < proxy_count) {
                        current_block = 11739054925370445424;
                        break;
                    }
                    p2 = select_proxy(FIFOLY, pd, proxy_count, &mut offset);
                    if p2.is_null() {
                        current_block = 11739054925370445424;
                        break;
                    }
                    if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p2) {
                        current_block = 2220405792722996547;
                        break;
                    }
                    p1 = p2;
                }
                match current_block {
                    2220405792722996547 => {}
                    _ => {
                        (*p3).ip = target_ip;
                        (*p3).port = target_port;
                        if SUCCESS as core::ffi::c_int != chain_step(&mut ns, p1, p3) {
                            current_block = 16306980487779480232;
                        } else {
                            current_block = 3634396408142324656;
                        }
                    }
                }
            }
        }
        9883066750544168046 => {
            proxychains_write_log(
                b"\n!!!need more proxies!!!\n\0" as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char,
            );
            current_block = 2220405792722996547;
        }
        _ => {}
    }
    match current_block {
        2220405792722996547 => {
            release_all(pd, proxy_count);
            if ns != -(1 as core::ffi::c_int) {
                close(ns);
            }
            *__errno_location() = ETIMEDOUT;
            return -(1 as core::ffi::c_int);
        }
        16306980487779480232 => {
            if ns != -(1 as core::ffi::c_int) {
                close(ns);
            }
            *__errno_location() = ECONNREFUSED;
            return -(1 as core::ffi::c_int);
        }
        _ => {
            proxychains_write_log(
                b" ...  OK\n\0" as *const u8 as *const core::ffi::c_char as *mut core::ffi::c_char,
            );
            dup2(ns, sock);
            close(ns);
            return 0 as core::ffi::c_int;
        }
    };
}
static mut servbyname_lock: pthread_mutex_t = pthread_mutex_t {
    __data: __pthread_mutex_s {
        __lock: 0,
        __count: 0,
        __owner: 0,
        __nusers: 0,
        __kind: 0,
        __spins: 0,
        __elision: 0,
        __list: __pthread_internal_list {
            __prev: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
            __next: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
        },
    },
};
#[no_mangle]
pub unsafe extern "C" fn core_initialize() {
    pthread_mutex_init(&mut servbyname_lock, 0 as *const pthread_mutexattr_t);
}
#[no_mangle]
pub unsafe extern "C" fn core_unload() {
    pthread_mutex_destroy(&mut servbyname_lock);
}
unsafe extern "C" fn gethostbyname_data_setstring(
    mut data: *mut gethostbyname_data,
    mut name: *mut core::ffi::c_char,
) {
    snprintf(
        ((*data).addr_name).as_mut_ptr(),
        ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
        b"%s\0" as *const u8 as *const core::ffi::c_char,
        name,
    );
    (*data).hostent_space.h_name = ((*data).addr_name).as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn proxy_gethostbyname_old(
    mut name: *const core::ffi::c_char,
) -> *mut hostent {
    let mut current_block: u64;
    static mut hostent_space: hostent = hostent {
        h_name: 0 as *const core::ffi::c_char as *mut core::ffi::c_char,
        h_aliases: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
    };
    static mut resolved_addr: in_addr_t = 0;
    static mut resolved_addr_p: *mut core::ffi::c_char =
        0 as *const core::ffi::c_char as *mut core::ffi::c_char;
    static mut addr_name: [core::ffi::c_char; 256] = [0; 256];
    let mut pipe_fd: [core::ffi::c_int; 2] = [0; 2];
    let mut buff: [core::ffi::c_char; 256] = [0; 256];
    let mut addr: in_addr_t = 0;
    let mut pid: pid_t = 0;
    let mut status: core::ffi::c_int = 0;
    let mut ret: core::ffi::c_int = 0;
    let mut l: size_t = 0;
    let mut hp: *mut hostent = 0 as *mut hostent;
    hostent_space.h_addr_list = &mut resolved_addr_p;
    *hostent_space.h_addr_list = &mut resolved_addr as *mut in_addr_t as *mut core::ffi::c_char;
    resolved_addr = 0 as in_addr_t;
    if pc_isnumericipv4(name) != 0 {
        strcpy(buff.as_mut_ptr(), name);
        current_block = 16000220506512563866;
    } else {
        gethostname(
            buff.as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
        );
        if strcmp(buff.as_mut_ptr(), name) == 0 {
            current_block = 16000220506512563866;
        } else {
            memset(
                buff.as_mut_ptr() as *mut core::ffi::c_void,
                0 as core::ffi::c_int,
                ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
            );
            loop {
                hp = gethostent();
                if hp.is_null() {
                    break;
                }
                if strcmp((*hp).h_name, name) == 0 {
                    return hp;
                }
            }
            ret = pipe(pipe_fd.as_mut_ptr());
            if ret == 0 as core::ffi::c_int {
                fcntl(pipe_fd[0 as core::ffi::c_int as usize], F_SETFD, FD_CLOEXEC);
                fcntl(pipe_fd[1 as core::ffi::c_int as usize], F_SETFD, FD_CLOEXEC);
            }
            if ret != 0 {
                current_block = 1665517376558617089;
            } else {
                pid = fork() as pid_t;
                match pid {
                    0 => {
                        proxychains_write_log(
                            b"|DNS-request| %s \n\0" as *const u8 as *const core::ffi::c_char
                                as *mut core::ffi::c_char,
                            name,
                        );
                        close(pipe_fd[0 as core::ffi::c_int as usize]);
                        dup2(
                            pipe_fd[1 as core::ffi::c_int as usize],
                            1 as core::ffi::c_int,
                        );
                        close(pipe_fd[1 as core::ffi::c_int as usize]);
                        execlp(
                            b"proxyresolv\0" as *const u8 as *const core::ffi::c_char,
                            b"proxyresolv\0" as *const u8 as *const core::ffi::c_char,
                            name,
                            NULL,
                        );
                        perror(
                            b"can't exec proxyresolv\0" as *const u8 as *const core::ffi::c_char,
                        );
                        exit(2 as core::ffi::c_int);
                    }
                    -1 => {
                        close(pipe_fd[0 as core::ffi::c_int as usize]);
                        close(pipe_fd[1 as core::ffi::c_int as usize]);
                        perror(b"can't fork\0" as *const u8 as *const core::ffi::c_char);
                        current_block = 1665517376558617089;
                    }
                    _ => {
                        close(pipe_fd[1 as core::ffi::c_int as usize]);
                        waitpid(pid as __pid_t, &mut status, 0 as core::ffi::c_int);
                        buff[0 as core::ffi::c_int as usize] = 0 as core::ffi::c_char;
                        read(
                            pipe_fd[0 as core::ffi::c_int as usize],
                            &mut buff as *mut [core::ffi::c_char; 256] as *mut core::ffi::c_void,
                            ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
                        );
                        close(pipe_fd[0 as core::ffi::c_int as usize]);
                        current_block = 16000220506512563866;
                    }
                }
            }
        }
    }
    match current_block {
        16000220506512563866 => {
            l = strlen(buff.as_mut_ptr());
            if !(l == 0) {
                if buff[l.wrapping_sub(1 as size_t) as usize] as core::ffi::c_int == '\n' as i32 {
                    buff[l.wrapping_sub(1 as size_t) as usize] = 0 as core::ffi::c_char;
                }
                addr = inet_addr(buff.as_mut_ptr());
                if !(addr == -(1 as core::ffi::c_int) as in_addr_t) {
                    memcpy(
                        *hostent_space.h_addr_list as *mut core::ffi::c_void,
                        &mut addr as *mut in_addr_t as *const core::ffi::c_void,
                        ::core::mem::size_of::<in_addr>() as size_t,
                    );
                    hostent_space.h_name = addr_name.as_mut_ptr();
                    snprintf(
                        addr_name.as_mut_ptr(),
                        ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
                        b"%s\0" as *const u8 as *const core::ffi::c_char,
                        buff.as_mut_ptr(),
                    );
                    hostent_space.h_length =
                        ::core::mem::size_of::<in_addr_t>() as core::ffi::c_int;
                    hostent_space.h_addrtype = AF_INET;
                    proxychains_write_log(
                        b"|DNS-response| %s is %s\n\0" as *const u8 as *const core::ffi::c_char
                            as *mut core::ffi::c_char,
                        name,
                        inet_ntoa(*(&mut addr as *mut in_addr_t as *mut in_addr)),
                    );
                    return &mut hostent_space;
                }
            }
            proxychains_write_log(
                b"|DNS-response|: %s lookup error\n\0" as *const u8 as *const core::ffi::c_char
                    as *mut core::ffi::c_char,
                name,
            );
        }
        _ => {}
    }
    return 0 as *mut hostent;
}
#[no_mangle]
pub unsafe extern "C" fn proxy_gethostbyname(
    mut name: *const core::ffi::c_char,
    mut data: *mut gethostbyname_data,
) -> *mut hostent {
    let mut hdb_res: ip_type4 = ip_type4 { octet: [0; 4] };
    let mut buff: [core::ffi::c_char; 256] = [0; 256];
    (*data).resolved_addr_p[0 as core::ffi::c_int as usize] =
        &mut (*data).resolved_addr as *mut in_addr_t as *mut core::ffi::c_char;
    (*data).resolved_addr_p[1 as core::ffi::c_int as usize] = 0 as *mut core::ffi::c_char;
    (*data).hostent_space.h_addr_list = ((*data).resolved_addr_p).as_mut_ptr();
    (*data).hostent_space.h_aliases = &mut *((*data).resolved_addr_p)
        .as_mut_ptr()
        .offset(1 as core::ffi::c_int as isize)
        as *mut *mut core::ffi::c_char;
    (*data).resolved_addr = 0 as in_addr_t;
    (*data).hostent_space.h_addrtype = AF_INET;
    (*data).hostent_space.h_length = ::core::mem::size_of::<in_addr_t>() as core::ffi::c_int;
    if pc_isnumericipv4(name) != 0 {
        (*data).resolved_addr = inet_addr(name);
    } else {
        gethostname(
            buff.as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
        );
        if strcmp(buff.as_mut_ptr(), name) == 0 {
            (*data).resolved_addr = inet_addr(buff.as_mut_ptr());
            if (*data).resolved_addr == -(1 as core::ffi::c_int) as in_addr_t {
                (*data).resolved_addr = IPT4_LOCALHOST.as_int;
            }
        } else {
            hdb_res = hostsreader_get_numeric_ip_for_name(name);
            if hdb_res.as_int != IPT4_INVALID.as_int {
                (*data).resolved_addr = hdb_res.as_int as in_addr_t;
            } else {
                (*data).resolved_addr =
                    (rdns_get_ip_for_host(name as *mut core::ffi::c_char, strlen(name))).as_int
                        as in_addr_t;
                if (*data).resolved_addr == IPT4_INVALID.as_int {
                    return 0 as *mut hostent;
                }
            }
        }
    }
    gethostbyname_data_setstring(data, name as *mut core::ffi::c_char);
    return &mut (*data).hostent_space;
}
#[no_mangle]
pub unsafe extern "C" fn proxy_freeaddrinfo(mut res: *mut addrinfo) {
    free(res as *mut core::ffi::c_void);
}
unsafe extern "C" fn mygetservbyname_r(
    mut name: *const core::ffi::c_char,
    mut proto: *const core::ffi::c_char,
    mut result_buf: *mut servent,
    mut _buf: *mut core::ffi::c_char,
    mut _buflen: size_t,
    mut result: *mut *mut servent,
) -> core::ffi::c_int {
    let mut res: *mut servent = 0 as *mut servent;
    let mut ret: core::ffi::c_int = 0;
    pthread_mutex_lock(&mut servbyname_lock);
    res = getservbyname(name, proto);
    if !res.is_null() {
        *result_buf = *res;
        *result = result_buf;
        ret = 0 as core::ffi::c_int;
    } else {
        *result = 0 as *mut servent;
        ret = ENOENT;
    }
    pthread_mutex_unlock(&mut servbyname_lock);
    return ret;
}
unsafe extern "C" fn looks_like_numeric_ipv6(
    mut node: *const core::ffi::c_char,
) -> core::ffi::c_int {
    if (strchr(node, ':' as i32)).is_null() {
        return 0 as core::ffi::c_int;
    }
    let mut p: *const core::ffi::c_char = node;
    loop {
        let fresh23 = p;
        p = p.offset(1);
        match *fresh23 as core::ffi::c_int {
            0 => return 1 as core::ffi::c_int,
            58 | 46 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 65 | 66 | 67 | 68 | 69
            | 70 | 97 | 98 | 99 | 100 | 101 | 102 => {}
            _ => return 0 as core::ffi::c_int,
        }
    }
}
unsafe extern "C" fn my_inet_aton(
    mut node: *const core::ffi::c_char,
    mut space: *mut addrinfo_data,
) -> core::ffi::c_int {
    let mut ret: core::ffi::c_int = 0;
    (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in)).sin_family =
        AF_INET as sa_family_t;
    ret = inet_aton(
        node,
        &mut (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in))
            .sin_addr,
    );
    if ret != 0 || looks_like_numeric_ipv6(node) == 0 {
        return ret;
    }
    ret = inet_pton(
        AF_INET6,
        node,
        &mut (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in6))
            .sin6_addr as *mut in6_addr as *mut core::ffi::c_void,
    );
    if ret != 0 {
        (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in6))
            .sin6_family = AF_INET6 as sa_family_t;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn proxy_getaddrinfo(
    mut node: *const core::ffi::c_char,
    mut service: *const core::ffi::c_char,
    mut hints: *const addrinfo,
    mut res: *mut *mut addrinfo,
) -> core::ffi::c_int {
    let mut ghdata: gethostbyname_data = gethostbyname_data {
        hostent_space: hostent {
            h_name: 0 as *const core::ffi::c_char as *mut core::ffi::c_char,
            h_aliases: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
            h_addrtype: 0,
            h_length: 0,
            h_addr_list: 0 as *const *mut core::ffi::c_char as *mut *mut core::ffi::c_char,
        },
        resolved_addr: 0,
        resolved_addr_p: [0 as *mut core::ffi::c_char; 2],
        addr_name: [0; 256],
    };
    let mut space: *mut addrinfo_data = 0 as *mut addrinfo_data;
    let mut se: *mut servent = 0 as *mut servent;
    let mut hp: *mut hostent = 0 as *mut hostent;
    let mut se_buf: servent = servent {
        s_name: 0 as *mut core::ffi::c_char,
        s_aliases: 0 as *mut *mut core::ffi::c_char,
        s_port: 0,
        s_proto: 0 as *mut core::ffi::c_char,
    };
    let mut p: *mut addrinfo = 0 as *mut addrinfo;
    let mut buf: [core::ffi::c_char; 1024] = [0; 1024];
    let mut port: core::ffi::c_int = 0;
    let mut af: core::ffi::c_int = AF_INET;
    space = calloc(
        1 as size_t,
        ::core::mem::size_of::<addrinfo_data>() as size_t,
    ) as *mut addrinfo_data;
    if space.is_null() {
        return EAI_MEMORY;
    }
    if !node.is_null() && my_inet_aton(node, space) == 0 {
        's_76: {
            if !(!hints.is_null() && (*hints).ai_flags & AI_NUMERICHOST != 0) {
                if proxychains_resolver as core::ffi::c_uint
                    == DNSLF_FORKEXEC as core::ffi::c_int as core::ffi::c_uint
                {
                    hp = proxy_gethostbyname_old(node);
                } else {
                    hp = proxy_gethostbyname(node, &mut ghdata);
                }
                if !hp.is_null() {
                    memcpy(
                        &mut (*(&mut (*space).sockaddr_space as *mut sockaddr_storage
                            as *mut sockaddr_in))
                            .sin_addr as *mut in_addr
                            as *mut core::ffi::c_void,
                        *(*hp).h_addr_list as *const core::ffi::c_void,
                        ::core::mem::size_of::<in_addr_t>() as size_t,
                    );
                    break 's_76;
                }
            }
            free(space as *mut core::ffi::c_void);
            return EAI_NONAME;
        }
    } else if !node.is_null() {
        af = (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in))
            .sin_family as core::ffi::c_int;
    } else if node.is_null() && (*hints).ai_flags & AI_PASSIVE == 0 {
        let ref mut fresh22 = (*(&mut (*space).sockaddr_space as *mut sockaddr_storage
            as *mut sockaddr_in))
            .sin_family;
        *fresh22 = AF_INET as sa_family_t;
        af = *fresh22 as core::ffi::c_int;
        memcpy(
            &mut (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in))
                .sin_addr as *mut in_addr as *mut core::ffi::c_void,
            b"\x7F\0\0\x01\0" as *const u8 as *const core::ffi::c_char as *const core::ffi::c_void,
            4 as size_t,
        );
    }
    if !service.is_null() {
        mygetservbyname_r(
            service,
            0 as *const core::ffi::c_char,
            &mut se_buf,
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 1024]>() as size_t,
            &mut se,
        );
    }
    port = if !se.is_null() {
        (*se).s_port
    } else {
        htons(atoi(if !service.is_null() {
            service
        } else {
            b"0\0" as *const u8 as *const core::ffi::c_char
        }) as uint16_t) as core::ffi::c_int
    };
    if af == AF_INET {
        (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in)).sin_port =
            port as in_port_t;
    } else {
        (*(&mut (*space).sockaddr_space as *mut sockaddr_storage as *mut sockaddr_in6)).sin6_port =
            port as in_port_t;
    }
    p = &mut (*space).addrinfo_space;
    *res = p;
    if p as size_t == space as size_t {
    } else {
        __assert_fail(
            b"(size_t)p == (size_t) space\0" as *const u8 as *const core::ffi::c_char,
            b"/home/adysec/\xE8\xA7\x86\xE9\xA2\x91/proxychains-ng-master/proxychains-C/src/core.c\0"
                as *const u8 as *const core::ffi::c_char,
            1013 as core::ffi::c_uint,
            __ASSERT_FUNCTION.as_ptr(),
        );
    }
    // duplicate assertion block removed (generated artifact that is never
    // reached differently from previous check). Keeping code minimal to
    // avoid unused-label warning.
    (*p).ai_addr = &mut (*space).sockaddr_space as *mut sockaddr_storage as *mut core::ffi::c_void
        as *mut sockaddr;
    if !node.is_null() {
        snprintf(
            ((*space).addr_name).as_mut_ptr(),
            ::core::mem::size_of::<[core::ffi::c_char; 256]>() as size_t,
            b"%s\0" as *const u8 as *const core::ffi::c_char,
            node,
        );
    }
    (*p).ai_canonname = ((*space).addr_name).as_mut_ptr();
    (*p).ai_next = 0 as *mut addrinfo;
    (*space).sockaddr_space.ss_family = af as sa_family_t;
    (*p).ai_family = (*space).sockaddr_space.ss_family as core::ffi::c_int;
    (*p).ai_addrlen = (if af == AF_INET {
        ::core::mem::size_of::<sockaddr_in>() as usize
    } else {
        ::core::mem::size_of::<sockaddr_in6>() as usize
    }) as socklen_t;
    if !hints.is_null() {
        (*p).ai_socktype = (*hints).ai_socktype;
        (*p).ai_flags = (*hints).ai_flags;
        (*p).ai_protocol = (*hints).ai_protocol;
        if (*p).ai_socktype == 0 && (*p).ai_protocol == IPPROTO_TCP as core::ffi::c_int {
            (*p).ai_socktype = SOCK_STREAM as core::ffi::c_int;
        }
    } else {
        (*p).ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
    }
    return 0 as core::ffi::c_int;
}
