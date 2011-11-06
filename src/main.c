/***************************************************************************
                          main.c  -  description

    begin                : Tue May 14 2002
    copyright            :  netcreature (C) 2002
    email                : netcreature@users.sourceforge.net
 ***************************************************************************/
 /*     GPL */
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char *optarg;
extern int optind, opterr, optopt;

#include "common.h"

static void usage(char** argv) {
	printf("\nUsage:	 %s [h] [f] config_file program_name [arguments]\n"
		"\t for example : proxychains telnet somehost.com\n"
		"More help in README file\n", argv[0]);
}

int check_path(char* path) {
	if(!path) return 0;
	return access(path, R_OK) != -1;
}

static const char* dll_name = "libproxychains4.so";

static const char* dll_dirs[] = {
	".",
	LIB_DIR,
	"/lib",
	"/usr/lib",
	"/usr/local/lib",
	"/lib64",
	NULL
};

int main(int argc, char *argv[]) {
	char *path = NULL;
	char buf[256];
	char pbuf[256];
	int opt;
	int start_argv = 1;

	while ((opt = getopt(argc, argv, "hf:")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv);
				return EXIT_SUCCESS;
			case 'f':
				path = (char *)optarg;
				if(!path) {
					printf("error: no path supplied.\n");
					return(EXIT_FAILURE);
				}
				start_argv = 3;
				break;
			default: /* '?' */
				usage(argv);
				exit(EXIT_FAILURE);
			}
	}

	/* check if path of config file has not been passed via command line */
	if(!path) {
		// priority 1: env var PROXYCHAINS_CONF_FILE
		path = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR);
		if(check_path(path)) goto have;
		
		// priority 2; proxychains conf in actual dir
		path = getcwd(buf, sizeof(buf));
		snprintf(pbuf, sizeof(pbuf), "%s/%s", path, PROXYCHAINS_CONF_FILE);
		path = pbuf;
		if(check_path(path)) goto have;
		
		// priority 3; $HOME/.proxychains/proxychains.conf
		path = getenv("HOME");
		snprintf(pbuf, sizeof(pbuf), "%s/.proxychains/%s", path, PROXYCHAINS_CONF_FILE);
		path = pbuf;
		if(check_path(path)) goto have;
		
		// priority 4: /etc/proxychains.conf
		path = "/etc/proxychains.conf";
		if(check_path(path)) goto have;
		perror("couldnt find configuration file");
		return 1;
	}
	
	have:

	printf(LOG_PREFIX "config file found: %s\n", path);

	/* Set PROXYCHAINS_CONF_FILE to get proxychains lib to use new config file. */
	setenv(PROXYCHAINS_CONF_FILE_ENV_VAR, path, 1);


	// search DLL
	size_t i = 0;
	const char* prefix = NULL;

	while(dll_dirs[i]) {
		snprintf(buf, sizeof(buf), "%s/%s", dll_dirs[i], dll_name);
		if(access(buf, R_OK) != -1) {
			prefix = dll_dirs[i];
			break;
		}
		i++;
	}

	if(!prefix) {
		printf("couldnt locate %s\n", dll_name);
		return EXIT_FAILURE;
	}
	printf(LOG_PREFIX "preloading %s/%s\n", prefix, dll_name);
	
	snprintf(buf, sizeof(buf), "LD_PRELOAD=%s/%s", prefix, dll_name);

	putenv(buf);
	execvp(argv[start_argv], &argv[start_argv]);
	perror("proxychains can't load process....");

	return EXIT_FAILURE;
}
