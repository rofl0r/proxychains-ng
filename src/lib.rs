// Crate root for proxychains-rs.
// We keep the old module namespace `crate::src::*` by creating a nested
// `src` module (files live under src/src/).
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(c_variadic)]
#![feature(extern_types)]
// label_break_value stabilized in old compilers; remove feature and
// allow static mutable references across the crate so the translated C
// code (which intentionally uses global mutable statics) doesn't spam
// rust-2024 compatibility warnings.
#![allow(static_mut_refs)]

// Expose internal modules at the crate root directly so modules are available
// as `crate::common`, `crate::core`, etc. This avoids requiring a top-level
// `lib.rs` and keeps the on-disk layout unchanged.
#[path = "common.rs"]
pub mod common;

#[path = "core.rs"]
pub mod core;

#[path = "hostsreader.rs"]
pub mod hostsreader;

#[path = "libproxychains.rs"]
pub mod libproxychains;

#[path = "rdns.rs"]
pub mod rdns;

// Compatibility layer: provide a few symbols the Rust crate previously
// expected to be provided by the C helper sources (allocator_thread.c,
// version.c, etc). This allows the crate to build and run without
// linking the C static helpers.
#[path = "c_compat.rs"]
pub mod c_compat;
