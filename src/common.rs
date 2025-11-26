extern "C" {
    fn exit(__status: core::ffi::c_int) -> !;
    fn getenv(__name: *const core::ffi::c_char) -> *mut core::ffi::c_char;
    fn access(__name: *const core::ffi::c_char, __type: core::ffi::c_int) -> core::ffi::c_int;
    fn getcwd(__buf: *mut core::ffi::c_char, __size: size_t) -> *mut core::ffi::c_char;
    fn snprintf(
        __s: *mut core::ffi::c_char,
        __maxlen: size_t,
        __format: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
    fn perror(__s: *const core::ffi::c_char);
}
pub type size_t = usize;
pub const PROXYCHAINS_CONF_FILE_ENV_VAR: [core::ffi::c_char; 22] = unsafe {
    ::core::mem::transmute::<[u8; 22], [core::ffi::c_char; 22]>(*b"PROXYCHAINS_CONF_FILE\0")
};
pub const PROXYCHAINS_QUIET_MODE_ENV_VAR: [core::ffi::c_char; 23] = unsafe {
    ::core::mem::transmute::<[u8; 23], [core::ffi::c_char; 23]>(*b"PROXYCHAINS_QUIET_MODE\0")
};
pub const PROXYCHAINS_CONF_FILE: [core::ffi::c_char; 17] =
    unsafe { ::core::mem::transmute::<[u8; 17], [core::ffi::c_char; 17]>(*b"proxychains.conf\0") };
pub const R_OK: core::ffi::c_int = 4 as core::ffi::c_int;
pub const NULL: *mut core::ffi::c_void = 0 as *mut core::ffi::c_void;
#[no_mangle]
pub static mut proxy_type_strmap: [*const core::ffi::c_char; 3] = [
    b"http\0" as *const u8 as *const core::ffi::c_char,
    b"socks4\0" as *const u8 as *const core::ffi::c_char,
    b"socks5\0" as *const u8 as *const core::ffi::c_char,
];
#[no_mangle]
pub static mut chain_type_strmap: [*const core::ffi::c_char; 4] = [
    b"dynamic_chain\0" as *const u8 as *const core::ffi::c_char,
    b"strict_chain\0" as *const u8 as *const core::ffi::c_char,
    b"random_chain\0" as *const u8 as *const core::ffi::c_char,
    b"round_robin_chain\0" as *const u8 as *const core::ffi::c_char,
];
#[no_mangle]
pub static mut proxy_state_strmap: [*const core::ffi::c_char; 4] = [
    b"play\0" as *const u8 as *const core::ffi::c_char,
    b"down\0" as *const u8 as *const core::ffi::c_char,
    b"blocked\0" as *const u8 as *const core::ffi::c_char,
    b"busy\0" as *const u8 as *const core::ffi::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn pc_isnumericipv4(
    mut ipstring: *const core::ffi::c_char,
) -> core::ffi::c_int {
    let mut x: size_t = 0 as size_t;
    let mut n: size_t = 0 as size_t;
    let mut d: size_t = 0 as size_t;
    let mut wasdot: core::ffi::c_int = 0 as core::ffi::c_int;
    loop {
        match *ipstring.offset(x as isize) as core::ffi::c_int {
            0 => {
                break;
            }
            46 => {
                if n == 0 || wasdot != 0 {
                    return 0 as core::ffi::c_int;
                }
                d = d.wrapping_add(1);
                wasdot = 1 as core::ffi::c_int;
            }
            48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 => {
                n = n.wrapping_add(1);
                wasdot = 0 as core::ffi::c_int;
            }
            _ => return 0 as core::ffi::c_int,
        }
        x = x.wrapping_add(1);
    }
    if d == 3 as size_t && n >= 4 as size_t && n <= 12 as size_t {
        return 1 as core::ffi::c_int;
    }
    return 0 as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pc_stringfromipv4(
    mut ip_buf_4_bytes: *mut core::ffi::c_uchar,
    mut outbuf_16_bytes: *mut core::ffi::c_char,
) {
    let mut p: *mut core::ffi::c_uchar = 0 as *mut core::ffi::c_uchar;
    let mut o: *mut core::ffi::c_char = outbuf_16_bytes;
    let mut n: core::ffi::c_uchar = 0;
    p = ip_buf_4_bytes;
    while p < ip_buf_4_bytes.offset(4 as core::ffi::c_int as isize) {
        n = *p;
        if *p as core::ffi::c_int >= 100 as core::ffi::c_int {
            if *p as core::ffi::c_int >= 200 as core::ffi::c_int {
                let fresh0 = o;
                o = o.offset(1);
                *fresh0 = '2' as i32 as core::ffi::c_char;
            } else {
                let fresh1 = o;
                o = o.offset(1);
                *fresh1 = '1' as i32 as core::ffi::c_char;
            }
            n = (n as core::ffi::c_int % 100 as core::ffi::c_int) as core::ffi::c_uchar;
        }
        if *p as core::ffi::c_int >= 10 as core::ffi::c_int {
            let fresh2 = o;
            o = o.offset(1);
            *fresh2 =
                (n as core::ffi::c_int / 10 as core::ffi::c_int + '0' as i32) as core::ffi::c_char;
            n = (n as core::ffi::c_int % 10 as core::ffi::c_int) as core::ffi::c_uchar;
        }
        let fresh3 = o;
        o = o.offset(1);
        *fresh3 = (n as core::ffi::c_int + '0' as i32) as core::ffi::c_char;
        let fresh4 = o;
        o = o.offset(1);
        *fresh4 = '.' as i32 as core::ffi::c_char;
        p = p.offset(1);
    }
    *o.offset(-(1 as core::ffi::c_int) as isize) = 0 as core::ffi::c_char;
}
unsafe extern "C" fn check_path(mut path: *mut core::ffi::c_char) -> core::ffi::c_int {
    if path.is_null() {
        return 0 as core::ffi::c_int;
    }
    return (access(path, R_OK) != -(1 as core::ffi::c_int)) as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn get_config_path(
    mut default_path: *mut core::ffi::c_char,
    mut pbuf: *mut core::ffi::c_char,
    mut bufsize: size_t,
) -> *mut core::ffi::c_char {
    let mut buf: [core::ffi::c_char; 512] = [0; 512];
    let mut path: *mut core::ffi::c_char = default_path;
    if !(check_path(path) != 0) {
        path = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR.as_ptr());
        if !(check_path(path) != 0) {
            path = getcwd(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[core::ffi::c_char; 512]>() as size_t,
            );
            snprintf(
                pbuf,
                bufsize,
                b"%s/%s\0" as *const u8 as *const core::ffi::c_char,
                path,
                PROXYCHAINS_CONF_FILE.as_ptr(),
            );
            path = pbuf;
            if !(check_path(path) != 0) {
                path = getenv(b"HOME\0" as *const u8 as *const core::ffi::c_char);
                snprintf(
                    pbuf,
                    bufsize,
                    b"%s/.proxychains/%s\0" as *const u8 as *const core::ffi::c_char,
                    path,
                    PROXYCHAINS_CONF_FILE.as_ptr(),
                );
                path = pbuf;
                if !(check_path(path) != 0) {
                    path = getenv(b"HOME\0" as *const u8 as *const core::ffi::c_char);
                    snprintf(
                        pbuf,
                        bufsize,
                        b"%s/config/settings/%s\0" as *const u8 as *const core::ffi::c_char,
                        path,
                        PROXYCHAINS_CONF_FILE.as_ptr(),
                    );
                    path = pbuf;
                    if !(check_path(path) != 0) {
                        path = b"/etc/proxychains.conf\0" as *const u8 as *const core::ffi::c_char
                            as *mut core::ffi::c_char;
                        if !(check_path(path) != 0) {
                            path = b"/etc/proxychains.conf\0" as *const u8
                                as *const core::ffi::c_char
                                as *mut core::ffi::c_char;
                            if !(check_path(path) != 0) {
                                perror(
                                    b"couldnt find configuration file\0" as *const u8
                                        as *const core::ffi::c_char,
                                );
                                exit(1 as core::ffi::c_int);
                            }
                        }
                    }
                }
            }
        }
    }
    return path;
}
