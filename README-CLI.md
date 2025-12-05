# proxychains-cli

A CLI wrapper for `proxychains4` that generates configuration dynamically without needing a config file.

## Installation

After building proxychains-ng:
```bash
make install
```

The `proxychains-cli` script is installed to the same location as `proxychains4`.

## Basic Usage

```bash
proxychains-cli [options] program [args...]
```

## Options

| Option                                | Default      | Description                           |
|---------------------------------------|--------------|-----------------------------------------------|
| `-h, --help`                          |              | Print help and exit                           |
| `-v, --version`                       |              | Print version and exit                        |
| `-c, --chain MODE`                    | strict       | Chain mode: strict/dynamic/random/round_robin |
| `-l, --chain-len N`                   |              | Chain length (for random/round_robin)         |
| `-q, --quiet`                         |              | Quiet mode                                    |
| `-d, --dns MODE`                      | proxy        | DNS: proxy/old/off/IP:PORT                    |
| `-S, --dns-subnet N`                  | 224          | Remote DNS subnet (0-255)                     |
| `-R, --read-timeout MS`               | 15000        | TCP read timeout (ms)                         |
| `-T, --connect-timeout MS`            | 8000         | TCP connect timeout (ms)                      |
| `-n, --localnet CIDR`                 |              | Bypass proxy for CIDR (repeatable)            |
| `--dnat "SRC DST"`                    |              | DNAT mapping (repeatable)                     |
| `-P, --proxy "IP PORT [ USER PASS ]"` |              | Add proxy (repeatable)                        |
| `--config`                            |              | Print config and exit                         |
| `--proxychains-path PATH`             | proxychains4 | Path to proxychains4 binary                   |

## Examples

### Example 1: Basic SOCKS5 proxy

```bash
proxychains-cli -P "socks5 127.0.0.1 1080" curl example.com
```

**Config passed to proxychains4 (fd 3):**
```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5	127.0.0.1	1080
```

### Example 2: Proxy with authentication

```bash
proxychains-cli -P "socks5 127.0.0.1 1080 myuser mypass" wget file.tar.gz
```

**Config (fd 3):**
```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5	127.0.0.1	1080	myuser	mypass
```

### Example 3: Multiple proxies (chain)

```bash
proxychains-cli \
  -c dynamic \
  -P "socks5 10.0.0.1 1080" \
  -P "http 10.0.0.2 8080" \
  curl example.com
```

**Config (fd 3):**
```
dynamic_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5	10.0.0.1	1080
http	10.0.0.2	8080
```

### Example 4: Random chain with length

```bash
proxychains-cli \
  -c random \
  -l 2 \
  -P "socks5 10.0.0.1 1080" \
  -P "socks5 10.0.0.2 1080" \
  -P "socks5 10.0.0.3 1080" \
  firefox
```

**Config (fd 3):**
```
random_chain
chain_len = 2
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5	10.0.0.1	1080
socks5	10.0.0.2	1080
socks5	10.0.0.3	1080
```

### Example 5: With localnet bypass

```bash
proxychains-cli \
  -n 192.168.0.0/16 \
  -n 10.0.0.0/8 \
  -P "socks5 proxy.example.com 1080" \
  ssh server.local
```

**Config (fd 3):**
```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 192.168.0.0/16
localnet 10.0.0.0/8
[ProxyList]
socks5	proxy.example.com	1080
```

### Example 6: Custom timeouts and DNS

```bash
proxychains-cli \
  -q \
  -d old \
  -R 30000 \
  -T 15000 \
  -P "socks5 127.0.0.1 9050" \
  curl example.com
```

**Config (fd 3):**
```
strict_chain
quiet_mode
proxy_dns_old
remote_dns_subnet 224
tcp_read_time_out 30000
tcp_connect_time_out 15000
[ProxyList]
socks5	127.0.0.1	9050
```

### Example 7: DNAT mapping

```bash
proxychains-cli \
  --dnat "1.1.1.1 2.2.2.2" \
  --dnat "8.8.8.8:53 10.0.0.1:5353" \
  -P "socks5 127.0.0.1 1080" \
  curl 1.1.1.1
```

**Config (fd 3):**
```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
dnat 1.1.1.1 2.2.2.2
dnat 8.8.8.8:53 10.0.0.1:5353
[ProxyList]
socks5	127.0.0.1	1080
```

## Special Cases

### Special characters in username/password

Use shell quoting to handle special characters:

```bash
# Password contains single quote: pass'word
proxychains-cli -P "socks5 127.0.0.1 1080 user pass'word" curl example.com

# Password contains double quote: pass"word
proxychains-cli -P 'socks5 127.0.0.1 1080 user pass"word' curl example.com

# Both quotes: user'name and pass"word
proxychains-cli -P $'socks5 127.0.0.1 1080 user\'name pass"word' curl example.com
```

### Viewing generated config

Use `--config` to print the configuration without running:

```bash
proxychains-cli -P "socks5 127.0.0.1 1080" --config
```

### Using different proxychains4 binary

```bash
proxychains-cli \
  --proxychains-path /opt/proxychains/bin/proxychains4 \
  -P "socks5 127.0.0.1 1080" \
  curl example.com
```

## How it works

1. `proxychains-cli` parses command-line options
2. Generates a proxychains.conf format configuration
3. Passes the config to `proxychains4` via file descriptor 3
4. `proxychains4` reads from `PROXYCHAINS_CONFIG_FD=3` instead of a file
5. The target program is executed with proxy hooks

No temporary files are created.

## Zsh Completion

Copy `completions/zsh/_proxychains-cli` to your zsh completions directory:

```bash
cp completions/zsh/_proxychains-cli /usr/local/share/zsh/site-functions/
```
