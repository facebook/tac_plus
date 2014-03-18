/*
 * $Id: tac_pwd.c,v 1.15 2006-12-13 01:11:37 heas Exp $
 *
 * Copyright (c) 1995-1998 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.
 *
 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Program to des encrypt a password like Unix.
 * It prompts for the password to encrypt.
 * You can optionally supply a salt to verify a password.
 * Usage: tac_pwd [salt]
 */

#include <config.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#include <time.h>

#if HAVE_MALLOC_H
# include <malloc.h>
#else
# include <stdlib.h>
#endif

#include <errno.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif

#include "md5.h"
#define MD5_LEN 16

void	usage(void);

int
main(int argc, char **argv)
{
    char		*crypt();
    char		buf[24],
			pass[25],
			*salt = NULL;
    char		*result;
    extern char		*optarg;
    extern int		optind;
    char		*prompt = "Password to be encrypted: ";
    int			opt_e = 0, opt_m = 0,
			n;
    struct termios	t;

    while ((n = getopt(argc, argv, "emh")) != EOF) {
	switch (n) {
	case 'e':
	    opt_e++;
	    break;
	case 'm':
        opt_m++;
        break;
	case 'h':
	    usage();
	    exit(0);
	    break;
	default:
	    usage();
	    exit(1);
	}
    }

    if (optind < argc) {
	salt = argv[optind];
    }

    if (opt_e) {
	if (tcgetattr(STDIN_FILENO, &t)) {
	    perror("could not get terminal characteristics");
	    exit(1);
	}
	t.c_lflag &= (~ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }

    write(1, prompt, strlen(prompt));
    n = read(0, pass, sizeof(pass));
    pass[n-1] = '\0';

    if (opt_e) {
	write(1, "\n", strlen("\n"));
	t.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }

    if (!opt_m) {
        if (!salt) {
    	int i, r, r1, r2;

    	r1 = r2 = 0;

    	srand(time(0));

    	for (i = 0; i <= 1; i++) {

    	    r = rand();

    	    r = r & 127;

    	    if (r < 46)
    		r += 46;

    	    if (r > 57 && r < 65)
    		r += 7;

    	    if (r > 90 && r < 97)
    		r += 6;

    	    if (r > 122)
    		r -= 5;

    	    if (i == 0)
    		r1 = r;

    	    if (i == 1)
    		r2 = r;
    	}

    	sprintf(buf, "%c%c", r1, r2);
    	salt = buf;
        }

        result = crypt(pass, salt);

        write(1, result, strlen(result));
        write(1, "\n", 1);        
    } else {
        char newpass[8];
        
        MD5_CTX mdcontext;
        u_char digest[16];
        char pwdigesthex[33];
        int i;

        strncpy(newpass, pass, sizeof(newpass));

        MD5Init(&mdcontext);
        MD5Update(&mdcontext, (u_char *)newpass, sizeof(newpass));
        MD5Final((u_char *) digest, &mdcontext);

        /* Convert to Hex */
        static const char hex[] = "0123456789abcdef";

        for (i=0;i<MD5_LEN;i++) {
            pwdigesthex[i+i] = hex[digest[i] >> 4];
            pwdigesthex[i+i+1] = hex[digest[i] & 0x0f];
        }
        pwdigesthex[i+i]='\0';
        
        write(1, pwdigesthex, strlen(pwdigesthex));
        write(1, "\n", 1);
        
    }

    return(0);
}

void
usage(void)
{
    fprintf(stderr, "Usage: tac_pwd [-eh] [<salt>]\n");
    fprintf(stderr, "\t-e\tdo not echo the password\n"
            "\t-m\tuse MD5 Encryption\n"
		    "\t-h\tdisplay this message\n");

    return;
}
