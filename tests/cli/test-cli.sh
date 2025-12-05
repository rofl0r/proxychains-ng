#!/bin/sh
# Comprehensive tests for proxychains-cli
# Run from project root: ./tests/cli/test-cli.sh

set -e
cd "$(dirname "$0")/../.."

CLI="./src/proxychains-cli"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() {
  PASS=$((PASS + 1))
  printf "${GREEN}✓${NC} %s\n" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf "${RED}✗${NC} %s\n" "$1"
  echo "  Expected: $2"
  echo "  Got: $3"
}

# Check if output contains a substring
# check_contains "description" "substring" "output"
check_contains() {
  if echo "$3" | grep -q "$2"; then
    pass "$1"
  else
    fail "$1" "contains '$2'" "$3"
  fi
}

# Check if output does not contain a substring
# check_not_contains "description" "substring" "output"
check_not_contains() {
  if ! echo "$3" | grep -q "$2"; then
    pass "$1"
  else
    fail "$1" "not contains '$2'" "$3"
  fi
}

echo "=== proxychains-cli Test Suite ==="
echo ""

# ============================================================
echo "--- Basic Options ---"
# ============================================================

# -h/--help
output=$($CLI -h 2>&1)
check_contains "-h shows usage" "Usage:" "$output"

output=$($CLI --help 2>&1)
check_contains "--help shows usage" "Usage:" "$output"

# -v/--version
output=$($CLI -v 2>&1)
check_contains "-v shows version" "proxychains-cli" "$output"

output=$($CLI --version 2>&1)
check_contains "--version shows version" "proxychains-cli" "$output"

# ============================================================
echo ""
echo "--- Chain Options ---"
# ============================================================

output=$($CLI -c strict -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-c strict" "strict_chain" "$output"

output=$($CLI -c dynamic -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-c dynamic" "dynamic_chain" "$output"

output=$($CLI -c random -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-c random" "random_chain" "$output"

output=$($CLI -c round_robin -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-c round_robin" "round_robin_chain" "$output"

output=$($CLI --chain strict -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--chain strict" "strict_chain" "$output"

# -l/--chain-len
output=$($CLI -c random -l 3 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-l 3" "chain_len = 3" "$output"

output=$($CLI -c random --chain-len 5 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--chain-len 5" "chain_len = 5" "$output"

# ============================================================
echo ""
echo "--- Output Options ---"
# ============================================================

output=$($CLI -q -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-q quiet mode" "quiet_mode" "$output"

output=$($CLI --quiet -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--quiet" "quiet_mode" "$output"

# ============================================================
echo ""
echo "--- DNS Options ---"
# ============================================================

output=$($CLI -d proxy -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-d proxy" "proxy_dns" "$output"

output=$($CLI -d old -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-d old" "proxy_dns_old" "$output"

output=$($CLI -d off -P "socks5 127.0.0.1 1080" --config 2>&1)
check_not_contains "-d off (no proxy_dns)" "proxy_dns" "$output"

output=$($CLI -d 127.0.0.1:1053 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-d IP:PORT daemon" "proxy_dns_daemon 127.0.0.1:1053" "$output"

output=$($CLI --dns proxy -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--dns proxy" "proxy_dns" "$output"

# -S/--dns-subnet
output=$($CLI -S 10 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-S 10" "remote_dns_subnet 10" "$output"

output=$($CLI --dns-subnet 127 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--dns-subnet 127" "remote_dns_subnet 127" "$output"

# ============================================================
echo ""
echo "--- Timeout Options ---"
# ============================================================

output=$($CLI -R 5000 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-R 5000" "tcp_read_time_out 5000" "$output"

output=$($CLI --read-timeout 10000 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--read-timeout" "tcp_read_time_out 10000" "$output"

output=$($CLI -T 3000 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-T 3000" "tcp_connect_time_out 3000" "$output"

output=$($CLI --connect-timeout 6000 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--connect-timeout" "tcp_connect_time_out 6000" "$output"

# ============================================================
echo ""
echo "--- Network Options ---"
# ============================================================

# -n/--localnet
output=$($CLI -n 192.168.0.0/16 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-n localnet" "localnet 192.168.0.0/16" "$output"

output=$($CLI --localnet 10.0.0.0/8 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--localnet" "localnet 10.0.0.0/8" "$output"

# Multiple localnets
output=$($CLI -n 192.168.0.0/16 -n 10.0.0.0/8 -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "multiple -n (first)" "localnet 192.168.0.0/16" "$output"
check_contains "multiple -n (second)" "localnet 10.0.0.0/8" "$output"

# --dnat
output=$($CLI --dnat "1.1.1.1 2.2.2.2" -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--dnat" "dnat 1.1.1.1 2.2.2.2" "$output"

# ============================================================
echo ""
echo "--- Proxy Options ---"
# ============================================================

# -P/--proxy with different types (quoted format)
output=$($CLI -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "-P socks5" "socks5" "$output"
check_contains "-P IP" "127.0.0.1" "$output"
check_contains "-P port" "1080" "$output"

output=$($CLI -P "socks4 10.0.0.1 9050" --config 2>&1)
check_contains "-P socks4" "socks4" "$output"

output=$($CLI -P "http 192.168.1.1 8080" --config 2>&1)
check_contains "-P http" "http" "$output"

output=$($CLI -P "raw 10.0.0.1 12345" --config 2>&1)
check_contains "-P raw" "raw" "$output"

# Proxy with user/pass
output=$($CLI -P "socks5 127.0.0.1 1080 user pass" --config 2>&1)
check_contains "-P with auth user" "user" "$output"
check_contains "-P with auth pass" "pass" "$output"

# Multiple proxies
output=$($CLI -P "socks5 127.0.0.1 1080" -P "http 10.0.0.1 8080" --config 2>&1)
check_contains "multi proxy (first)" "socks5.*127.0.0.1.*1080" "$output"
check_contains "multi proxy (second)" "http.*10.0.0.1.*8080" "$output"

# --proxy long form
output=$($CLI --proxy "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--proxy" "socks5" "$output"

# ============================================================
echo ""
echo "--- Debug Options ---"
# ============================================================

# --config
output=$($CLI -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "--config outputs ProxyList" "[ProxyList]" "$output"

# --proxychains-path
output=$($CLI -P "socks5 127.0.0.1 1080" --proxychains-path echo test 2>&1)
check_contains "--proxychains-path echo" "test" "$output"

# ============================================================
echo ""
echo "--- Error Handling ---"
# ============================================================

# No proxy error
output=$($CLI echo test 2>&1) || true
check_contains "no proxy error" "No proxy specified" "$output"

# No program error (without --config)
output=$($CLI -P "socks5 127.0.0.1 1080" 2>&1) || true
check_contains "no program error" "No program specified" "$output"

# Unknown option
output=$($CLI --unknown-option 2>&1) || true
check_contains "unknown option error" "Unknown option" "$output"

# ============================================================
echo ""
echo "--- Edge Cases: Special Characters ---"
# ============================================================

# IPv6 address
output=$($CLI -n "::1/128" -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "IPv6 localnet" "localnet ::1/128" "$output"

# Localnet with port
output=$($CLI -n "192.168.1.0:80/24" -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "localnet with port" "localnet 192.168.1.0:80/24" "$output"

# DNAT with ports
output=$($CLI --dnat "1.1.1.1:443 2.2.2.2:8443" -P "socks5 127.0.0.1 1080" --config 2>&1)
check_contains "dnat with ports" "dnat 1.1.1.1:443 2.2.2.2:8443" "$output"

# ============================================================
echo ""
echo "--- BUG FIX: Program args not parsed as CLI args ---"
# ============================================================

# curl -v should not be parsed as CLI -v
output=$($CLI -P "socks5 127.0.0.1 1080" --proxychains-path echo curl -v example.com 2>&1)
check_contains "curl -v passes through" "curl -v example.com" "$output"
check_not_contains "curl -v not treated as --version" "proxychains-cli" "$output"

# Program with multiple options
output=$($CLI -P "socks5 127.0.0.1 1080" --proxychains-path echo wget --no-check-certificate -O - example.com 2>&1)
check_contains "program args pass through" "wget --no-check-certificate -O - example.com" "$output"

# Using -- separator
output=$($CLI -P "socks5 127.0.0.1 1080" --proxychains-path echo -- -v -h --help 2>&1)
if echo "$output" | grep -F -- "-v -h --help" > /dev/null; then
  pass "-- separator works"
else
  fail "-- separator works" "contains '-v -h --help'" "$output"
fi

# ============================================================
echo ""
echo "--- Combined Options ---"
# ============================================================

output=$($CLI \
  -q \
  -c random \
  -l 2 \
  -d proxy \
  -S 224 \
  -R 15000 \
  -T 8000 \
  -n 192.168.0.0/16 \
  -n 10.0.0.0/8 \
  -P "socks5 127.0.0.1 9050" \
  -P "http 10.0.0.1 8080" \
  --config 2>&1)

check_contains "combined: chain" "random_chain" "$output"
check_contains "combined: chain_len" "chain_len = 2" "$output"
check_contains "combined: quiet" "quiet_mode" "$output"
check_contains "combined: dns" "proxy_dns" "$output"
check_contains "combined: subnet" "remote_dns_subnet 224" "$output"
check_contains "combined: read_timeout" "tcp_read_time_out 15000" "$output"
check_contains "combined: connect_timeout" "tcp_connect_time_out 8000" "$output"
check_contains "combined: localnet1" "localnet 192.168.0.0/16" "$output"
check_contains "combined: localnet2" "localnet 10.0.0.0/8" "$output"
check_contains "combined: proxy1" "socks5" "$output"
check_contains "combined: proxy2" "http" "$output"

# ============================================================
echo ""
echo "--- FD Config Passing Test ---"
# ============================================================

# Generate config and verify format
output=$($CLI -P "socks5 127.0.0.1 9050" --config 2>&1)
check_contains "config has chain" "_chain" "$output"
check_contains "config has ProxyList" "[ProxyList]" "$output"
check_contains "config has proxy entry" "socks5 *127.0.0.1 *9050" "$output"

# ============================================================
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"

if [ $FAIL -gt 0 ]; then
  exit 1
fi
