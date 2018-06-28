/*
 * Copyright (c) 1991 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in  source and binary  forms  are permitted
 * provided that the  above copyright  notice  and this paragraph are
 * duplicated in all  such forms.  Inclusion  in a product or release
 * as part of  a  package  for  sale is not  agreed to.  Storing this
 * software in a  nonvolatile  storage  device  characterized  as  an
 * integrated circuit providing  read  only  memory (ROM), either  as
 * source code or  machine executeable  instructions is similarly not
 * agreed to.  THIS  SOFTWARE IS  PROVIDED ``AS IS'' AND  WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT  LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE
 */
#ifndef lint
char Copyright[]=
    "@(#) Copyright (c) 1991 David G. Koontz\n All rights reserved.\n";
#endif
/*
 *	fdes.c - faster implementation of DES algorithm.
 */

#include "config.h"
#include "fdes.h"
#include "des_ip.h"
#include "des_iip.h"
#include "des_key.h"
#include "des_s_p.h"

/* Key Schedule permuted for S Box input: */
static union block_48 K_S[16];
static union block_48 *key_start;
static int des_mode;

#pragma weak    tac_des
#pragma weak    tac_des_loadkey
#pragma weak    tac_set_des_mode

void
tac_set_des_mode(int encode)
{
    if (encode) {
	key_start = &K_S[0];
	des_mode = SHIFT_FOR_ENCRYPT;
    } else {
	key_start = &K_S[15];
	des_mode = SHIFT_FOR_DECRYPT;
    }
}

void
tac_des_loadkey(unsigned char *key, int shift)
{
    unsigned i,j;
    union block_48 data;

    if (!shift)			          /* key lookup table always shifts */
	for (i = 0; i < 8; i++)
	    data.string[i] = key[i] >> 1;
    else
	for (i = 0; i < 8; i++)
	    data.string[i] = key[i];

    for ( j = 0; j < 16; j++)		  /* key load must be re-entrant    */
	K_S[j].AB[0] = K_S[j].AB[1] = 0;

    for (i = 0; i < 8; i++) {		    /* 8 bytes (56 bits) of key	     */
	for(j = 0; j < 16;j++) {	    /* load K_S[0-16] byte at a time */
	    K_S[j].AB[0] |= KEY[i][data.string[i]][j][0];
	    K_S[j].AB[1] |= KEY[i][data.string[i]][j][1];
	}
    }
}

static void
no_ip_des(union LR_block *block)
{
    unsigned int round;
    int shift;
    unsigned long temp_f;
    union block_48 pre_S, *k_s;

    k_s = key_start;
    shift = des_mode;

    for (round = 0; round < 8; round++) {     /* f(R,K), 16 double rounds */

	/* Expansion Permutation, E XOR K */
	temp_f = block->LR[RR];	/* L/R reg. is R31,R0...R30 (D0-D31) format */
	pre_S.AB[0] = temp_f & 0x3f3f3f3f ^ k_s->AB[0];	     /* S1S3S5S7 */
	pre_S.AB[1] = ((temp_f >> 4 | temp_f << 28) & 0x3f3f3f3f) ^ k_s->AB[1];
	k_s += shift;					     /* S2S4S6S8 */

	/* S Box and P lookup:  temp_f = f(R,K) */
	temp_f  = S_P[0][pre_S.string[S1]] | S_P[1][pre_S.string[S2]]
	        | S_P[2][pre_S.string[S3]] | S_P[3][pre_S.string[S4]]
		| S_P[4][pre_S.string[S5]] | S_P[5][pre_S.string[S6]]
	        | S_P[6][pre_S.string[S7]] | S_P[7][pre_S.string[S8]];

	/* f(R,K) EXOR L */
	temp_f ^= block->LR[LL];	    /* temp_f is new R */
	block->LR[LL] = temp_f;		    /* update L register */

	/* Repeat round (temp_f carried through) */
	pre_S.AB[0] = temp_f & 0x3f3f3f3f ^ k_s->AB[0];
	pre_S.AB[1] = ((temp_f >> 4 | temp_f << 28) & 0x3f3f3f3f) ^ k_s->AB[1];
	k_s += shift;

	temp_f  = S_P[0][pre_S.string[S1]] | S_P[1][pre_S.string[S2]]
	        | S_P[2][pre_S.string[S3]] | S_P[3][pre_S.string[S4]]
		| S_P[4][pre_S.string[S5]] | S_P[5][pre_S.string[S6]]
	        | S_P[6][pre_S.string[S7]] | S_P[7][pre_S.string[S8]];

	temp_f ^= block->LR[RR];	    /* L is old R */
	block->LR[RR] = temp_f;		    /* update R register */
    }
    /* had L/R swap here */
}

void
tac_des(union LR_block *block)
{
    unsigned long temp;
    union LR_block data;

    data.LR[LL] = block->LR[LL];
    data.LR[RR] = block->LR[RR];

    temp    = IP[ 0][data.string[0]] | IP[ 1][data.string[1]] |
	      IP[ 2][data.string[2]] | IP[ 3][data.string[3]] |
	      IP[ 4][data.string[4]] | IP[ 5][data.string[5]] |
	      IP[ 6][data.string[6]] | IP[ 7][data.string[7]];

    data.LR[LL] =
	      IP[ 8][data.string[0]] | IP[ 9][data.string[1]] |
	      IP[10][data.string[2]] | IP[11][data.string[3]] |
	      IP[12][data.string[4]] | IP[13][data.string[5]] |
	      IP[14][data.string[6]] | IP[15][data.string[7]];

    data.LR[RR] = temp;

    no_ip_des(&data);

    temp    = IIP[ 0][data.string[0]] | IIP[ 1][data.string[1]] |
	      IIP[ 2][data.string[2]] | IIP[ 3][data.string[3]] |
	      IIP[ 4][data.string[4]] | IIP[ 5][data.string[5]] |
	      IIP[ 6][data.string[6]] | IIP[ 7][data.string[7]];

    block->LR[AA] =
	      IIP[ 8][data.string[0]] | IIP[ 9][data.string[1]] |
	      IIP[10][data.string[2]] | IIP[11][data.string[3]] |
	      IIP[12][data.string[4]] | IIP[13][data.string[5]] |
	      IIP[14][data.string[6]] | IIP[15][data.string[7]];

    block->LR[BB] = temp;
}
