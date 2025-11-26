extern "C" {
    pub type sockaddr_x25;
    pub type sockaddr_un;
    pub type sockaddr_ns;
    pub type sockaddr_iso;
    pub type sockaddr_ipx;
    pub type sockaddr_inarp;
    pub type sockaddr_eon;
    pub type sockaddr_dl;
    pub type sockaddr_ax25;
    pub type sockaddr_at;
    fn socket(
        __domain: core::ffi::c_int,
        __type: core::ffi::c_int,
        __protocol: core::ffi::c_int,
    ) -> core::ffi::c_int;
    fn sendto(
        __fd: core::ffi::c_int,
        __buf: *const core::ffi::c_void,
        __n: size_t,
        __flags: core::ffi::c_int,
        __addr: __CONST_SOCKADDR_ARG,
        __addr_len: socklen_t,
    ) -> ssize_t;
    fn recvfrom(
        __fd: core::ffi::c_int,
        __buf: *mut core::ffi::c_void,
        __n: size_t,
        __flags: core::ffi::c_int,
        __addr: __SOCKADDR_ARG,
        __addr_len: *mut socklen_t,
    ) -> ssize_t;
    fn abort() -> !;
    fn memcpy(
        __dest: *mut core::ffi::c_void,
        __src: *const core::ffi::c_void,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn close(__fd: core::ffi::c_int) -> core::ffi::c_int;
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    fn htons(__hostshort: uint16_t) -> uint16_t;
    static mut proxychains_resolver: dns_lookup_flavor;
    fn at_init();
    fn at_get_host_for_ip(ip: ip_type4, readbuf: *mut core::ffi::c_char) -> size_t;
    fn at_get_ip_for_host(host: *mut core::ffi::c_char, len: size_t) -> ip_type4;
}
pub type size_t = usize;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __socklen_t = core::ffi::c_uint;
pub type ssize_t = isize;
pub type socklen_t = __socklen_t;
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
pub union __SOCKADDR_ARG {
    pub __sockaddr__: *mut sockaddr,
    pub __sockaddr_at__: *mut sockaddr_at,
    pub __sockaddr_ax25__: *mut sockaddr_ax25,
    pub __sockaddr_dl__: *mut sockaddr_dl,
    pub __sockaddr_eon__: *mut sockaddr_eon,
    pub __sockaddr_in__: *mut sockaddr_in,
    pub __sockaddr_in6__: *mut sockaddr_in6,
    pub __sockaddr_inarp__: *mut sockaddr_inarp,
    pub __sockaddr_ipx__: *mut sockaddr_ipx,
    pub __sockaddr_iso__: *mut sockaddr_iso,
    pub __sockaddr_ns__: *mut sockaddr_ns,
    pub __sockaddr_un__: *mut sockaddr_un,
    pub __sockaddr_x25__: *mut sockaddr_x25,
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
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: In6AddrUnion,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union In6AddrUnion {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union __CONST_SOCKADDR_ARG {
    pub __sockaddr__: *const sockaddr,
    pub __sockaddr_at__: *const sockaddr_at,
    pub __sockaddr_ax25__: *const sockaddr_ax25,
    pub __sockaddr_dl__: *const sockaddr_dl,
    pub __sockaddr_eon__: *const sockaddr_eon,
    pub __sockaddr_in__: *const sockaddr_in,
    pub __sockaddr_in6__: *const sockaddr_in6,
    pub __sockaddr_inarp__: *const sockaddr_inarp,
    pub __sockaddr_ipx__: *const sockaddr_ipx,
    pub __sockaddr_iso__: *const sockaddr_iso,
    pub __sockaddr_ns__: *const sockaddr_ns,
    pub __sockaddr_un__: *const sockaddr_un,
    pub __sockaddr_x25__: *const sockaddr_x25,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union ip_type4 {
    pub octet: [core::ffi::c_uchar; 4],
    pub as_int: uint32_t,
}
pub type at_msgtype = core::ffi::c_uint;
pub const ATM_EXIT: at_msgtype = 3;
pub const ATM_FAIL: at_msgtype = 2;
pub const ATM_GETNAME: at_msgtype = 1;
pub const ATM_GETIP: at_msgtype = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct at_msghdr {
    pub msgtype: core::ffi::c_uchar,
    pub reserved: core::ffi::c_char,
    pub datalen: core::ffi::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct at_msg {
    pub h: at_msghdr,
    pub m: AtMsgData,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union AtMsgData {
    pub host: [core::ffi::c_char; 260],
    pub ip: ip_type4,
}
pub type dns_lookup_flavor = core::ffi::c_uint;
pub const DNSLF_RDNS_DAEMON: dns_lookup_flavor = 3;
pub const DNSLF_RDNS_THREAD: dns_lookup_flavor = 2;
pub const DNSLF_RDNS_START: dns_lookup_flavor = 2;
pub const DNSLF_FORKEXEC: dns_lookup_flavor = 1;
pub const DNSLF_LIBC: dns_lookup_flavor = 0;
pub const PF_INET: core::ffi::c_int = 2 as core::ffi::c_int;
pub const AF_INET: core::ffi::c_int = PF_INET;
pub const SOCK_CLOEXEC_0: core::ffi::c_int = 0 as core::ffi::c_int;
static mut rdns_server: sockaddr_in = sockaddr_in {
    sin_family: 0,
    sin_port: 0,
    sin_addr: in_addr { s_addr: 0 },
    sin_zero: [0; 8],
};
#[no_mangle]
pub unsafe extern "C" fn rdns_daemon_get_host_for_ip(
    mut ip: ip_type4,
    mut readbuf: *mut core::ffi::c_char,
) -> size_t {
    let mut msg: at_msg = {
        let mut init = at_msg {
            h: {
                let mut init = at_msghdr {
                    msgtype: ATM_GETNAME as core::ffi::c_int as core::ffi::c_uchar,
                    reserved: 0,
                    datalen: htons(4 as uint16_t) as core::ffi::c_ushort,
                };
                init
            },
            m: AtMsgData { ip: ip },
        };
        init
    };
    let mut fd: core::ffi::c_int = socket(
        AF_INET,
        SOCK_DGRAM as core::ffi::c_int | SOCK_CLOEXEC_0,
        0 as core::ffi::c_int,
    );
    sendto(
        fd,
        &mut msg as *mut at_msg as *const core::ffi::c_void,
        (::core::mem::size_of::<at_msghdr>() as size_t).wrapping_add(4 as size_t),
        0 as core::ffi::c_int,
        __CONST_SOCKADDR_ARG {
            __sockaddr__: &mut rdns_server as *mut sockaddr_in as *mut core::ffi::c_void
                as *const sockaddr,
        },
        ::core::mem::size_of::<sockaddr_in>() as socklen_t,
    );
    recvfrom(
        fd,
        &mut msg as *mut at_msg as *mut core::ffi::c_void,
        ::core::mem::size_of::<at_msg>() as size_t,
        0 as core::ffi::c_int,
        __SOCKADDR_ARG {
            __sockaddr__: 0 as *mut core::ffi::c_void as *mut sockaddr,
        },
        0 as *mut socklen_t,
    );
    close(fd);
    msg.h.datalen = ntohs(msg.h.datalen as uint16_t) as core::ffi::c_ushort;
    if msg.h.datalen == 0 || msg.h.datalen as core::ffi::c_int > 256 as core::ffi::c_int {
        return 0 as size_t;
    }
    memcpy(
        readbuf as *mut core::ffi::c_void,
        (msg.m.host).as_mut_ptr() as *const core::ffi::c_void,
        msg.h.datalen as size_t,
    );
    return (msg.h.datalen as core::ffi::c_int - 1 as core::ffi::c_int) as size_t;
}
unsafe extern "C" fn rdns_daemon_get_ip_for_host(
    mut host: *mut core::ffi::c_char,
    mut len: size_t,
) -> ip_type4 {
    let mut msg: at_msg = {
        let mut init = at_msg {
            h: {
                let mut init = at_msghdr {
                    msgtype: ATM_GETIP as core::ffi::c_int as core::ffi::c_uchar,
                    reserved: 0,
                    datalen: 0,
                };
                init
            },
            m: AtMsgData { host: [0; 260] },
        };
        init
    };
    if len >= 256 as size_t {
        return ip_type4 {
            as_int: -(1 as core::ffi::c_int) as uint32_t,
        };
    }
    memcpy(
        (msg.m.host).as_mut_ptr() as *mut core::ffi::c_void,
        host as *const core::ffi::c_void,
        len.wrapping_add(1 as size_t),
    );
    msg.h.datalen = htons(len.wrapping_add(1 as size_t) as uint16_t) as core::ffi::c_ushort;
    let mut fd: core::ffi::c_int = socket(
        AF_INET,
        SOCK_DGRAM as core::ffi::c_int | SOCK_CLOEXEC_0,
        0 as core::ffi::c_int,
    );
    sendto(
        fd,
        &mut msg as *mut at_msg as *const core::ffi::c_void,
        (::core::mem::size_of::<at_msghdr>() as size_t)
            .wrapping_add(len)
            .wrapping_add(1 as size_t),
        0 as core::ffi::c_int,
        __CONST_SOCKADDR_ARG {
            __sockaddr__: &mut rdns_server as *mut sockaddr_in as *mut core::ffi::c_void
                as *const sockaddr,
        },
        ::core::mem::size_of::<sockaddr_in>() as socklen_t,
    );
    recvfrom(
        fd,
        &mut msg as *mut at_msg as *mut core::ffi::c_void,
        ::core::mem::size_of::<at_msg>() as size_t,
        0 as core::ffi::c_int,
        __SOCKADDR_ARG {
            __sockaddr__: 0 as *mut core::ffi::c_void as *mut sockaddr,
        },
        0 as *mut socklen_t,
    );
    close(fd);
    if ntohs(msg.h.datalen as uint16_t) as core::ffi::c_int != 4 as core::ffi::c_int {
        return ip_type4 {
            as_int: -(1 as core::ffi::c_int) as uint32_t,
        };
    }
    return msg.m.ip;
}
#[no_mangle]
pub unsafe extern "C" fn rdns_resolver_string(
    mut flavor: dns_lookup_flavor,
) -> *const core::ffi::c_char {
    static mut tab: [[core::ffi::c_char; 7]; 4] = unsafe {
        [
            ::core::mem::transmute::<[u8; 7], [core::ffi::c_char; 7]>(*b"off\0\0\0\0"),
            ::core::mem::transmute::<[u8; 7], [core::ffi::c_char; 7]>(*b"old\0\0\0\0"),
            ::core::mem::transmute::<[u8; 7], [core::ffi::c_char; 7]>(*b"thread\0"),
            ::core::mem::transmute::<[u8; 7], [core::ffi::c_char; 7]>(*b"daemon\0"),
        ]
    };
    return (tab[flavor as usize]).as_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn rdns_init(mut flavor: dns_lookup_flavor) {
    static mut init_done: core::ffi::c_int = 0 as core::ffi::c_int;
    if init_done == 0 {
        match flavor as core::ffi::c_uint {
            2 => {
                at_init();
            }
            3 | _ => {}
        }
    }
    init_done = 1 as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rdns_set_daemon(mut addr: *mut sockaddr_in) {
    rdns_server = *addr;
}
#[no_mangle]
pub unsafe extern "C" fn rdns_get_host_for_ip(
    mut ip: ip_type4,
    mut readbuf: *mut core::ffi::c_char,
) -> size_t {
    match proxychains_resolver as core::ffi::c_uint {
        2 => return at_get_host_for_ip(ip, readbuf),
        3 => return rdns_daemon_get_host_for_ip(ip, readbuf),
        _ => {
            abort();
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn rdns_get_ip_for_host(
    mut host: *mut core::ffi::c_char,
    mut len: size_t,
) -> ip_type4 {
    match proxychains_resolver as core::ffi::c_uint {
        2 => return at_get_ip_for_host(host, len),
        3 => return rdns_daemon_get_ip_for_host(host, len),
        _ => {
            abort();
        }
    };
}
