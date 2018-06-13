/*
 * $Id: expire.c,v 1.8 2006-12-13 01:11:37 heas Exp $
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

#include "tac_plus.h"
#include "expire.h"
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

/*
 * check a date for expiry. If the field specifies
 * a shell return PW_OK
 *
 * Return PW_OK if not expired
 * Return PW_EXPIRING if expiry is coming soon
 * Return PW_EXPIRED  if already expired
 */

#define SEC_IN_DAY ((time_t)(24*60*60))
#define WARNING_PERIOD ((time_t)14)

static char *monthname[] = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN",
				"JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
static int32_t days_ere_month[] = {0, 31, 59, 90, 120, 151,
				181, 212, 243, 273, 304, 334};

/*
 * compare the *date in a "month day year" format to the current day.  if
 * greater, return PW_EXPIRED, else PW_OK.
 */
int
check_expiration(char *date)
{
    int32_t day, month, year, leaps;
    time_t now, expiration, warning;
    char monthstr[10];
    int i;

    monthstr[0] = '\0';

    /* If no date or a shell, let it pass.  (Backward compatibility.) */
    if (date == NULL || (strlen(date) == 0) || (*date == '/'))
	return(PW_OK);

    /* Parse date string.  Fail it upon error. */
    if (sscanf(date, "%s %d %d", monthstr, &day, &year) != 3)
	return(PW_EXPIRED);

    for (i = 0; i < 3; i++) {
	monthstr[i] = toupper((int)monthstr[i]);
    }

    /* Compute the expiration date in days. */
    for (month = 0; month < 12; month++)
	if (strncmp(monthstr, monthname[month], 3) == 0)
	    break;

    if (month > 11)
	return(PW_EXPIRED);

    leaps = (year - 1969) / 4 + (((year % 4) == 0) && (month > 2));
    expiration = (((year - 1970) * 365) + days_ere_month[month] +
							(day - 1) + leaps);
    warning = expiration - WARNING_PERIOD;

    /* Get the current time (to the day) */
    now = time(NULL) / SEC_IN_DAY;

    if (now > expiration)
	return(PW_EXPIRED);

    if (now > warning)
	return(PW_EXPIRING);

    return(PW_OK);
}
