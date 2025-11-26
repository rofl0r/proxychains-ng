# proxychains-rs

This document is a concise usage and build guide for the proxychains-rs repository. It focuses on building, running and debugging the Rust port of proxychains, and also covers common issues.

---

## Overview

proxychains-rs is a Rust port of proxychains-ng. Its goal is to produce a shared library that can be injected into target programs using LD_PRELOAD and that behaves (including textual output) the same way as the original C implementation. The runtime artifact produced by this project is `libproxychains_rs.so`.

Main runtime artifact (release):

- `target/release/libproxychains_rs.so` — the shared object produced by Rust (cdylib).

Note: The supported runtime artifact is `target/release/libproxychains_rs.so`. The project does not rely on producing a compatibility copy named `libproxychains4.so` by default anymore.

Important: the repository uses some Rust nightly-only features in parts of the codebase (for example `c_variadic` / `extern_types`). Because of this, a nightly toolchain is required to build.

---

## Local build (recommended)

1. Ensure you have rustup installed and enable the nightly toolchain:

```bash
rustup toolchain install nightly
```

2. Build the project using cargo from the `proxychains-rs` directory:

```bash
# Build the Rust portion using the nightly toolchain
rustup run nightly cargo build -p proxychains_rs --release
```

This will produce the shared object under `target/release/libproxychains_rs.so`.

---

## Using with a target program (example)

To use proxychains-rs with any dynamically linked program that supports LD_PRELOAD, set the configuration file path and LD_PRELOAD the built shared object:

```bash
PROXYCHAINS_CONF_FILE=/etc/proxychains.conf LD_PRELOAD=target/release/libproxychains_rs.so curl -I https://www.baidu.com
```

If you are replacing an existing `proxychains4` script or binary (the C-based tool), the Rust version aims to be consistent in behavior and log text. Using `target/release/libproxychains_rs.so` as LD_PRELOAD should act as a drop-in replacement for the C artifact.

An example wrapper similar to `/usr/bin/proxychains`:

```sh
#!/bin/sh
echo "ProxyChains-5.0"
if [ $# = 0 ]; then
    echo "\tusage:"
    echo "\t\tproxychains <prog> [args]"
    exit
fi
export LD_PRELOAD=libproxychains_rs.so
exec "$@"
```

---

## Configuration and debugging options

- Configuration file search order (priority):
  1. `PROXYCHAINS_CONF_FILE` environment variable (or `-f` argument)
  2. `./proxychains.conf` in the current directory
  3. `$(HOME)/.proxychains/proxychains.conf`
  4. System config `/etc/proxychains.conf` (sysconfdir)

- Settings in the configuration file:
  - `quiet_mode` — suppresses the per-connection log lines (same as the C implementation).
  - `proxy_dns`, `proxy_dns_daemon`, `proxy_dns_old` — control remote-DNS (RDNS) behavior/modes.

- Environment variables:
  - `PROXYCHAINS_VERBOSE_DEBUG=1` — enable extra internal debug traces for development and troubleshooting.

---

## Frequently Asked Questions

- Q: Why is a nightly toolchain required to build?
  - A: The port uses Rust features that are currently only available on the nightly channel (for example `c_variadic` / `extern_types`). That's why the nightly toolchain is required.

---

## Future improvements (suggestions)

- Reduce or remove `unsafe` and `static mut` usage where practical and refactor key paths to be more idiomatic Rust (long-term goal).
- Improve cross-platform support.

---

