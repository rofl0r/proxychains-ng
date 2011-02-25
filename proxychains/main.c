/***************************************************************************
                          main.c  -  description
                             -------------------
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

int main(int argc, char *argv[])
{
  if(argc<2)
  {
        printf("\nUsage:   proxychains program_name [arguments]\n"
       	   "\t for example : proxychains telnet somehost.com\n"
                 "More help in README file\n");
        return 0 ;
  }
  putenv("LD_PRELOAD=/usr/lib/libproxychains.so");
  execvp(argv[1],&argv[1]);
  perror("proxychains can't load process....");
  return EXIT_SUCCESS;
}
