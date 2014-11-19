/*
 * Copyright (c) 2014, Konstantin Pugin. 
 * Based on Alexey Degtyarev`s implementation.
 * All rights reserved.
 *
 * GOST main header.
 *
 */


#include <string.h>

#define ALIGN(x) __attribute__ ((__aligned__(x)))

#define X(x, y, z) { \
    z->QWORD[0] = x->QWORD[0] ^ y->QWORD[0]; \
    z->QWORD[1] = x->QWORD[1] ^ y->QWORD[1]; \
    z->QWORD[2] = x->QWORD[2] ^ y->QWORD[2]; \
    z->QWORD[3] = x->QWORD[3] ^ y->QWORD[3]; \
    z->QWORD[4] = x->QWORD[4] ^ y->QWORD[4]; \
    z->QWORD[5] = x->QWORD[5] ^ y->QWORD[5]; \
    z->QWORD[6] = x->QWORD[6] ^ y->QWORD[6]; \
    z->QWORD[7] = x->QWORD[7] ^ y->QWORD[7]; \
}

#define __XLPS_FOR for (_i = 0; _i <= 7; _i++)
#define _datai _i

#define XLPS(x, y, data) { \
    register unsigned long long r0, r1, r2, r3, r4, r5, r6, r7; \
    int _i; \
    \
    r0 = x->QWORD[0] ^ y->QWORD[0]; \
    r1 = x->QWORD[1] ^ y->QWORD[1]; \
    r2 = x->QWORD[2] ^ y->QWORD[2]; \
    r3 = x->QWORD[3] ^ y->QWORD[3]; \
    r4 = x->QWORD[4] ^ y->QWORD[4]; \
    r5 = x->QWORD[5] ^ y->QWORD[5]; \
    r6 = x->QWORD[6] ^ y->QWORD[6]; \
    r7 = x->QWORD[7] ^ y->QWORD[7]; \
    \
    \
    __XLPS_FOR \
    {\
        data->QWORD[_datai]  = Ax[0][(r0 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[1][(r1 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[2][(r2 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[3][(r3 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[4][(r4 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[5][(r5 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[6][(r6 >> (_i << 3)) & 0xFF]; \
        data->QWORD[_datai] ^= Ax[7][(r7 >> (_i << 3)) & 0xFF]; \
    }\
}

#define ROUND(i, Ki, data) { \
    XLPS(Ki, (&C[i]), Ki); \
    XLPS(Ki, data, data); \
}

ALIGN(16) union uint512_u
{
    unsigned long long QWORD[8];
} uint512_u;

#include "const.h"

ALIGN(16) typedef struct GOST_Context
{
    ALIGN(16) unsigned char buffer[64];
    ALIGN(16) union uint512_u hash;
    ALIGN(16) union uint512_u h;
    ALIGN(16) union uint512_u N;
    ALIGN(16) union uint512_u Sigma;
    size_t bufsize;
    unsigned int digest_size;
} GOST_Context;

void GOST_Init(GOST_Context *CTX,
        const unsigned int digest_size);

void GOST_Update(GOST_Context *CTX, const unsigned char *data,
        size_t len); 

void GOST_Final(GOST_Context *CTX, unsigned char *digest);

void GOST_Cleanup(GOST_Context *CTX);
