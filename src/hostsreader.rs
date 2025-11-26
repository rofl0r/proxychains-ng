extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn fclose(__stream: *mut FILE) -> core::ffi::c_int;
    fn fopen(__filename: *const core::ffi::c_char, __modes: *const core::ffi::c_char) -> *mut FILE;
    fn fgets(
        __s: *mut core::ffi::c_char,
        __n: core::ffi::c_int,
        __stream: *mut FILE,
    ) -> *mut core::ffi::c_char;
    fn __ctype_b_loc() -> *mut *const core::ffi::c_ushort;
    fn memcpy(
        __dest: *mut core::ffi::c_void,
        __src: *const core::ffi::c_void,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn strcmp(__s1: *const core::ffi::c_char, __s2: *const core::ffi::c_char) -> core::ffi::c_int;
    fn pc_isnumericipv4(ipstring: *const core::ffi::c_char) -> core::ffi::c_int;
    fn inet_aton(__cp: *const core::ffi::c_char, __inp: *mut in_addr) -> core::ffi::c_int;
}
pub type size_t = usize;
pub type __uint32_t = u32;
pub type __off_t = core::ffi::c_long;
pub type __off64_t = core::ffi::c_long;
// Use libc's FILE for an unambiguous, shared FILE type across modules.
pub type FILE = ::libc::FILE;
pub type CtypeFlags = core::ffi::c_uint;
pub const _ISalnum: CtypeFlags = 8;
pub const _ISpunct: CtypeFlags = 4;
pub const _IScntrl: CtypeFlags = 2;
pub const _ISblank: CtypeFlags = 1;
pub const _ISgraph: CtypeFlags = 32768;
pub const _ISprint: CtypeFlags = 16384;
pub const _ISspace: CtypeFlags = 8192;
pub const _ISxdigit: CtypeFlags = 4096;
pub const _ISdigit: CtypeFlags = 2048;
pub const _ISalpha: CtypeFlags = 1024;
pub const _ISlower: CtypeFlags = 512;
pub const _ISupper: CtypeFlags = 256;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostsreader {
    pub f: *mut FILE,
    pub ip: *mut core::ffi::c_char,
    pub name: *mut core::ffi::c_char,
}
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union ip_type4 {
    pub octet: [core::ffi::c_uchar; 4],
    pub as_int: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
#[no_mangle]
pub unsafe extern "C" fn hostsreader_open(mut ctx: *mut hostsreader) -> core::ffi::c_int {
    (*ctx).f = fopen(
        b"/etc/hosts\0" as *const u8 as *const core::ffi::c_char,
        b"r\0" as *const u8 as *const core::ffi::c_char,
    ) as *mut FILE;
    if ((*ctx).f).is_null() {
        return 0 as core::ffi::c_int;
    }
    return 1 as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn hostsreader_close(mut ctx: *mut hostsreader) {
    fclose((*ctx).f);
}
#[no_mangle]
pub unsafe extern "C" fn hostsreader_get(
    mut ctx: *mut hostsreader,
    mut buf: *mut core::ffi::c_char,
    mut bufsize: size_t,
) -> core::ffi::c_int {
    loop {
        if (fgets(buf, bufsize as core::ffi::c_int, (*ctx).f)).is_null() {
            return 0 as core::ffi::c_int;
        }
        if *buf as core::ffi::c_int == '#' as i32 {
            continue;
        }
        let mut p: *mut core::ffi::c_char = buf;
        let mut l: size_t = bufsize;
        (*ctx).ip = p;
        while *p as core::ffi::c_int != 0
            && *(*__ctype_b_loc()).offset(*p as core::ffi::c_int as isize) as core::ffi::c_int
                & _ISspace as core::ffi::c_int as core::ffi::c_ushort as core::ffi::c_int
                == 0
            && l != 0
        {
            p = p.offset(1);
            l = l.wrapping_sub(1);
        }
        if l == 0 || *p == 0 || p == (*ctx).ip {
            continue;
        }
        *p = 0 as core::ffi::c_char;
        p = p.offset(1);
        while *p as core::ffi::c_int != 0
            && *(*__ctype_b_loc()).offset(*p as core::ffi::c_int as isize) as core::ffi::c_int
                & _ISspace as core::ffi::c_int as core::ffi::c_ushort as core::ffi::c_int
                != 0
            && l != 0
        {
            p = p.offset(1);
            l = l.wrapping_sub(1);
        }
        if l == 0 || *p == 0 {
            continue;
        }
        (*ctx).name = p;
        while *p as core::ffi::c_int != 0
            && *(*__ctype_b_loc()).offset(*p as core::ffi::c_int as isize) as core::ffi::c_int
                & _ISspace as core::ffi::c_int as core::ffi::c_ushort as core::ffi::c_int
                == 0
            && l != 0
        {
            p = p.offset(1);
            l = l.wrapping_sub(1);
        }
        if l == 0 || *p == 0 {
            continue;
        }
        *p = 0 as core::ffi::c_char;
        if pc_isnumericipv4((*ctx).ip) != 0 {
            return 1 as core::ffi::c_int;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn hostsreader_get_ip_for_name(
    mut name: *const core::ffi::c_char,
    mut buf: *mut core::ffi::c_char,
    mut bufsize: size_t,
) -> *mut core::ffi::c_char {
    let mut ctx: hostsreader = hostsreader {
        f: 0 as *mut FILE,
        ip: 0 as *mut core::ffi::c_char,
        name: 0 as *mut core::ffi::c_char,
    };
    let mut res: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    if hostsreader_open(&mut ctx) == 0 {
        return 0 as *mut core::ffi::c_char;
    }
    while hostsreader_get(&mut ctx, buf, bufsize) != 0 {
        if !(strcmp(ctx.name, name) == 0) {
            continue;
        }
        res = ctx.ip;
        break;
    }
    hostsreader_close(&mut ctx);
    return res;
}
pub const IPT4_INVALID: ip_type4 = ip_type4 {
    as_int: -(1 as core::ffi::c_int) as uint32_t,
};
#[no_mangle]
pub unsafe extern "C" fn hostsreader_get_numeric_ip_for_name(
    mut name: *const core::ffi::c_char,
) -> ip_type4 {
    let mut hres: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut buf: [core::ffi::c_char; 320] = [0; 320];
    hres = hostsreader_get_ip_for_name(
        name,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[core::ffi::c_char; 320]>() as size_t,
    );
    if !hres.is_null() {
        let mut c: in_addr = in_addr { s_addr: 0 };
        inet_aton(hres, &mut c);
        let mut res: ip_type4 = ip_type4 { octet: [0; 4] };
        memcpy(
            (res.octet).as_mut_ptr() as *mut core::ffi::c_void,
            &mut c.s_addr as *mut in_addr_t as *const core::ffi::c_void,
            4 as size_t,
        );
        return res;
    } else {
        return IPT4_INVALID;
    };
}
