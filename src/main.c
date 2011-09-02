/***************************************************************************
                          main.c  -  description
   q							 -------------------
    begin                : Tue May 14 2002
    copyright          :  netcreature (C) 2002
    email                 : netcreature@users.sourceforge.net
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


/*
* 	 well ... actually this file could be a shell script ... but C rulez :).
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char *optarg;
extern int optind, opterr, optopt

/*
 * XXX. Same thing is defined in proxychains main.c it
 * needs to be changed, too.
 */
#define PROXYCHAINS_CONF_FILE "PROXYCHAINS_CONF_FILE"

static usage(void)
{

		printf("\nUsage:	 %s [h] [f] config_file program_name [arguments]\n"
       	   "\t for example : proxychains telnet somehost.com\n"
										"More help in README file\n", argv[0], );
}

int main(int argc, char *argv[])
{
		char *path;

		path = NULL;

		while ((opt = getopt(argc, argv, "fh:")) != -1) {
				switch (opt) {
						case 'h':
								usage();
								break;
						case 'f':
								path = (char *)optarg;
								break;
						default: /* '?' */
								usage();
								exit(EXIT_FAILURE);
				}
  }

		printf("Proxychains are going to use %s as config file.\n", path);
		printf("argv = %s\n", argv[1]);

		/* Set PROXYCHAINS_CONF_FILE to get proxychains lib to
			 use new config file. */
		setenv(PROXYCHAINS_CONF_FILE, path, 1);

		/*XXX. proxychains might be installed in some different location */
  putenv("LD_PRELOAD=/usr/lib/libproxychains.so");
  execvp(argv[1],&argv[1]);
  perror("proxychains can't load process....");

  return EXIT_SUCCESS;
}
