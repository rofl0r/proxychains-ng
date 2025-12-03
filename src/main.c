/*   (C) 2011, 2012 rofl0r
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef IS_MAC
#define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>

#include "argparse.h"
#include "common.h"

static int usage(char **argv) {
	printf("\nUsage: %s [options] program [arguments]\n\n", argv[0]);

	printf("Config File:\n");
	printf("  -f, --config-file <path>     Use alternative config file\n");
	printf("      --ignore-config-file     Ignore config file completely\n\n");

	printf("Chain Mode:\n");
	printf("  -c, --chain [mode[:len]]     Set chain mode\n");
	printf("                               s|strict (default), d|dynamic,\n");
	printf("                               rr|round_robin, rd|random\n");
	printf("                               Optional :N for chain length (e.g. "
			 "rr:2)\n");
	printf("  -l, --chain-len <N>          Set chain length\n\n");

	printf("DNS Mode:\n");
	printf("  -d, --dns [mode]             Set DNS mode\n");
	printf("                               proxy (default), old, off\n");
	printf(
		"                               IP:PORT or [IPv6]:PORT for daemon\n\n");

	printf("Proxies (repeatable, URL format only):\n");
	printf("  -P, --proxy <url>            Add proxy (repeatable)\n");
	printf("                               Format: "
			 "protocol://[user:pass@]host:port\n");
	printf("                               Protocols: http, socks4, socks5, "
			 "socks5h, raw\n\n");

	printf("Network:\n");
	printf(
		"  -n, --localnet <spec>        Add localnet exclusion (repeatable)\n");
	printf("      --dnat <src-dst>         Add DNAT rule (repeatable)\n");
	printf("                               Format: src-dst (dash separator)\n");
	printf("  -S, --remote-dns-subnet <N>  Remote DNS subnet (0-255)\n\n");

	printf("Timeouts:\n");
	printf("  -R, --tcp-read-timeout <ms>  TCP read timeout\n");
	printf("  -T, --tcp-connect-timeout <ms> TCP connect timeout\n\n");

	printf("Output:\n");
	printf("  -q, --quiet                  Quiet mode (no output)\n");
	printf("      --no-quiet               Disable quiet mode\n");
	printf("  -D, --debug-level <N>        Debug level (0=silent, 1=basic, "
			 "2=verbose)\n\n");

	printf("Help:\n");
	printf("  -h, --help                   Show this help\n\n");

	printf("Examples:\n");
	printf("  %s curl https://example.com\n", argv[0]);
	printf("  %s -q -f /etc/proxychains.conf curl https://example.com\n",
			 argv[0]);
	printf("  %s -c strict -d proxy curl https://example.com\n", argv[0]);
	printf("  %s -P socks5://127.0.0.1:1080 curl https://example.com\n", argv[0]);
	printf("  %s --ignore-config-file -P socks5://tor:9050 curl "
			 "https://example.com\n\n",
			 argv[0]);

	printf("Priority: argv > env > config file\n\n");

	return EXIT_FAILURE;
}

static const char *dll_name = DLL_NAME;

static char own_dir[256];
static const char *dll_dirs[] = {
#ifndef SUPER_SECURE /* CVE-2015-3887 */
	".",
#endif
	own_dir, LIB_DIR, "/lib", "/usr/lib", "/usr/local/lib", "/lib64", NULL};

static void set_own_dir(const char *argv0) {
	size_t l = strlen(argv0);
	while (l && argv0[l - 1] != '/')
		l--;
	if (l == 0 || l >= sizeof(own_dir))
#ifdef SUPER_SECURE
		memcpy(own_dir, "/dev/null/", 11);
#else
		memcpy(own_dir, ".", 2);
#endif
	else {
		memcpy(own_dir, argv0, l - 1);
		own_dir[l] = 0;
	}
}

/* Helper to append to list with comma separator */
static void append_to_list(char *list, size_t max_size, const char *item) {
	if (strlen(list) > 0) {
		strncat(list, ",", max_size - strlen(list) - 1);
	}
	strncat(list, item, max_size - strlen(list) - 1);
}

/* Helper to check if arg starts with prefix */
static int arg_starts_with(const char *arg, const char *prefix) {
	return strncmp(arg, prefix, strlen(prefix)) == 0;
}

/**
 * Parse command line arguments and return CLI options
 * Returns: 0 on success, 1 on error (usage shown), 2 on help
 */
static int parse_arguments(int argc, char *argv[], cli_options *opts,
													 int *start_argv) {
	int tmp_chain_len;

	*start_argv = 1;
	memset(opts, 0, sizeof(*opts));

	/* Parse command line arguments */
	while (*start_argv < argc && argv[*start_argv][0] == '-') {
		const char *arg = argv[*start_argv];

		/* Help */
		if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
			return 2; /* Help requested */
		}

		/* Quiet mode */
		else if (!strcmp(arg, "-q") || !strcmp(arg, "--quiet")) {
			opts->has_quiet = 1;
			opts->quiet_mode = 1;
			(*start_argv)++;
		} else if (!strcmp(arg, "--no-quiet")) {
			opts->has_quiet = 1;
			opts->quiet_mode = 0;
			(*start_argv)++;
		}

		/* Config file */
		else if (!strcmp(arg, "-f") || !strcmp(arg, "--config-file")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->config_file_path = argv[*start_argv + 1];
			*start_argv += 2;
		} else if (!strcmp(arg, "--ignore-config-file")) {
			opts->ignore_config_file = 1;
			(*start_argv)++;
		}

		/* Chain mode */
		else if (!strcmp(arg, "-c") || !strcmp(arg, "--chain")) {
			if (*start_argv + 1 >= argc)
				return 1;
			if (parse_chain_mode(argv[*start_argv + 1], &opts->chain_mode,
													 &tmp_chain_len) != 0) {
				return 1;
			}
			opts->has_chain_mode = 1;
			if (tmp_chain_len > 0) {
				opts->has_chain_len = 1;
				opts->chain_len = tmp_chain_len;
			}
			*start_argv += 2;
		} else if (!strcmp(arg, "-l") || !strcmp(arg, "--chain-len")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_chain_len = 1;
			opts->chain_len = atoi(argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* DNS mode */
		else if (!strcmp(arg, "-d") || !strcmp(arg, "--dns")) {
			if (*start_argv + 1 >= argc)
				return 1;
			if (parse_dns_value(argv[*start_argv + 1], opts->dns_value,
													sizeof(opts->dns_value)) != 0) {
				return 1;
			}
			opts->has_dns_mode = 1;
			*start_argv += 2;
		}

		/* Debug level */
		else if (!strcmp(arg, "-D") || !strcmp(arg, "--debug-level")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_debug_level = 1;
			opts->debug_level = atoi(argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* Timeouts */
		else if (!strcmp(arg, "-R") || !strcmp(arg, "--tcp-read-timeout")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_tcp_read_timeout = 1;
			opts->tcp_read_timeout = atoi(argv[*start_argv + 1]);
			*start_argv += 2;
		} else if (!strcmp(arg, "-T") || !strcmp(arg, "--tcp-connect-timeout")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_tcp_connect_timeout = 1;
			opts->tcp_connect_timeout = atoi(argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* Remote DNS subnet */
		else if (!strcmp(arg, "-S") || !strcmp(arg, "--remote-dns-subnet")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_remote_dns_subnet = 1;
			opts->remote_dns_subnet = atoi(argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* Localnet (repeatable) */
		else if (!strcmp(arg, "-n") || !strcmp(arg, "--localnet")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_localnet = 1;
			append_to_list(opts->localnet_list, sizeof(opts->localnet_list),
										 argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* DNAT (repeatable) */
		else if (!strcmp(arg, "--dnat")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_dnat = 1;
			append_to_list(opts->dnat_list, sizeof(opts->dnat_list),
										 argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* Proxy (repeatable) */
		else if (!strcmp(arg, "-P") || !strcmp(arg, "--proxy")) {
			if (*start_argv + 1 >= argc)
				return 1;
			opts->has_proxy = 1;
			append_to_list(opts->proxy_list, sizeof(opts->proxy_list),
										 argv[*start_argv + 1]);
			*start_argv += 2;
		}

		/* Unknown option */
		else {
			fprintf(stderr, "Unknown option: %s\n", arg);
			return 1;
		}
	}

	/* Check if program name is provided */
	if (*start_argv >= argc) {
		return 1;
	}

	/* Validate CLI options */
	if (validate_cli_options(opts) != 0) {
		return 1;
	}

	return 0; /* Success */
}

int main(int argc, char *argv[]) {
	char *path = NULL;
	char buf[256];
	char pbuf[256];
	int start_argv;
	size_t i;
	const char *prefix = NULL;
	cli_options opts;
	int parse_result;

	/* Parse arguments */
	parse_result = parse_arguments(argc, argv, &opts, &start_argv);
	if (parse_result == 2) {
		return usage(argv); /* Help requested */
	}
	if (parse_result != 0) {
		return usage(argv); /* Parse error */
	}

	/* Handle config file */
	if (!opts.ignore_config_file) {
		path = get_config_path(opts.config_file_path, pbuf, sizeof(pbuf));
		if (!opts.quiet_mode)
			fprintf(stderr, LOG_PREFIX "config file found: %s\n", path);
		setenv(PROXYCHAINS_CONF_FILE_ENV_VAR, path, 1);
	} else {
		if (!opts.quiet_mode)
			fprintf(stderr, LOG_PREFIX "ignoring config file\n");
	}

	/* Serialize CLI options to environment variables */
	serialize_cli_options_to_env(&opts);

	/* Set quiet mode */
	if (opts.quiet_mode)
		setenv(PROXYCHAINS_QUIET_MODE_ENV_VAR, "1", 1);

	// search DLL

	Dl_info dli;
	dladdr(own_dir, &dli);
	set_own_dir(dli.dli_fname);

	i = 0;

	while (dll_dirs[i]) {
		snprintf(buf, sizeof(buf), "%s/%s", dll_dirs[i], dll_name);
		if (access(buf, R_OK) != -1) {
			prefix = dll_dirs[i];
			break;
		}
		i++;
	}

	if (!prefix) {
		fprintf(stderr, "couldnt locate %s\n", dll_name);
		return EXIT_FAILURE;
	}
	if (!opts.quiet_mode)
		fprintf(stderr, LOG_PREFIX "preloading %s/%s\n", prefix, dll_name);

#if defined(IS_MAC) || defined(IS_OPENBSD)
#define LD_PRELOAD_SEP ":"
#else
/* Dynlinkers for Linux and most BSDs seem to support space
   as LD_PRELOAD separator, with colon added only recently.
   We use the old syntax for maximum compat */
#define LD_PRELOAD_SEP " "
#endif

#ifdef IS_MAC
	putenv("DYLD_FORCE_FLAT_NAMESPACE=1");
#define LD_PRELOAD_ENV "DYLD_INSERT_LIBRARIES"
#else
#define LD_PRELOAD_ENV "LD_PRELOAD"
#endif
	char *old_val = getenv(LD_PRELOAD_ENV);
	snprintf(buf, sizeof(buf), LD_PRELOAD_ENV "=%s/%s%s%s", prefix, dll_name,
			/* append previous LD_PRELOAD content, if existent */
			old_val ? LD_PRELOAD_SEP : "", old_val ? old_val : "");
	putenv(buf);
	execvp(argv[start_argv], &argv[start_argv]);
	fprintf(stderr, "proxychains: can't load process '%s'.", argv[start_argv]);
	perror(" (hint: it's probably a typo)");

	return EXIT_FAILURE;
}
