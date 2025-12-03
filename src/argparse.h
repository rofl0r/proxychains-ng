#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <stddef.h>

/*
 * chain_type enum definition
 * Only define if not already defined by core.h
 * This allows argparse.h to be used both standalone (main.c)
 * and with core.h (libproxychains.c)
 */
#ifndef __CORE_HEADER
typedef enum {
  DYNAMIC_TYPE,
  STRICT_TYPE,
  RANDOM_TYPE,
  ROUND_ROBIN_TYPE
} chain_type;
#endif

/* Environment variable names for CLI options */
#define PROXYCHAINS_CLI_IGNORE_CONFIG "PROXYCHAINS_CLI_IGNORE_CONFIG"
#define PROXYCHAINS_CLI_CHAIN_MODE "PROXYCHAINS_CLI_CHAIN_MODE"
#define PROXYCHAINS_CLI_CHAIN_LEN "PROXYCHAINS_CLI_CHAIN_LEN"
#define PROXYCHAINS_CLI_DNS "PROXYCHAINS_CLI_DNS"
#define PROXYCHAINS_CLI_QUIET "PROXYCHAINS_CLI_QUIET"
#define PROXYCHAINS_CLI_DEBUG_LEVEL "PROXYCHAINS_CLI_DEBUG_LEVEL"
#define PROXYCHAINS_CLI_TCP_READ_TIMEOUT "PROXYCHAINS_CLI_TCP_READ_TIMEOUT"
#define PROXYCHAINS_CLI_TCP_CONNECT_TIMEOUT                                    \
  "PROXYCHAINS_CLI_TCP_CONNECT_TIMEOUT"
#define PROXYCHAINS_CLI_REMOTE_DNS_SUBNET "PROXYCHAINS_CLI_REMOTE_DNS_SUBNET"
#define PROXYCHAINS_CLI_LOCALNET "PROXYCHAINS_CLI_LOCALNET"
#define PROXYCHAINS_CLI_DNAT "PROXYCHAINS_CLI_DNAT"
#define PROXYCHAINS_CLI_PROXY "PROXYCHAINS_CLI_PROXY"
#define PROXYCHAINS_CLI_SHOW_CONFIG "PROXYCHAINS_CLI_SHOW_CONFIG"

/* Maximum lengths for string buffers */
#define MAX_CLI_STRING 4096

/* Structure to hold all parsed CLI options */
typedef struct {
  /* Config file options */
  int ignore_config_file;
  char *config_file_path;

  /* Chain options */
  int has_chain_mode;
  chain_type chain_mode;
  int has_chain_len;
  unsigned int chain_len;

  /* DNS options - consolidated into single value */
  int has_dns_mode;
  char dns_value[256]; /* "proxy", "old", "off", or "IP:PORT" */

  /* Quiet mode */
  int has_quiet;
  int quiet_mode;

  /* Debug level */
  int has_debug_level;
  int debug_level; /* 0=silent, 1=basic, 2=verbose */

  /* Timeouts */
  int has_tcp_read_timeout;
  int tcp_read_timeout;
  int has_tcp_connect_timeout;
  int tcp_connect_timeout;

  /* Remote DNS subnet */
  int has_remote_dns_subnet;
  unsigned int remote_dns_subnet;

  /* List directives - stored as comma/semicolon separated strings */
  int has_localnet;
  char localnet_list[MAX_CLI_STRING];

  int has_dnat;
  char dnat_list[MAX_CLI_STRING];

  int has_proxy;
  char proxy_list[MAX_CLI_STRING];

  /* Show config flag */
  int has_show_config;
  int show_config;
} cli_options;

/* Function declarations */

/**
 * Serialize CLI options to environment variables
 * Called by main.c before execvp()
 */
void serialize_cli_options_to_env(const cli_options *opts);

/**
 * Deserialize CLI options from environment variables
 * Called by libproxychains.c in get_chain_data()
 */
void deserialize_cli_options_from_env(cli_options *opts);

/**
 * Parse chain mode string with optional inline length
 * Examples: "strict", "s", "rr:2", "random:4"
 * Returns 0 on success, -1 on error
 */
int parse_chain_mode(const char *arg, chain_type *mode, int *chain_len);

/**
 * Parse DNS value - can be mode keyword or IP:PORT
 * Examples: "proxy", "off", "127.0.0.1:1053", "[::1]:1053"
 * Returns 0 on success, -1 on error
 */
int parse_dns_value(const char *arg, char *dns_value, size_t max_len);

/**
 * Validate CLI options after parsing
 * Returns 0 if valid, -1 if errors found (prints error messages)
 */
int validate_cli_options(const cli_options *opts);

#endif /* ARGPARSE_H */
