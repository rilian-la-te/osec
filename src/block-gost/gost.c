/*
 * Copyright (c) 2014, Konstantin Pugin. 
 * Based on Alexey Degtyarev`s implementation.
 * All rights reserved.
 *
 * GOST Hash main file.
 *
 */


#include "gost.h"

#define BSWAP64(x) \
    (((x & 0xFF00000000000000ULL) >> 56) | \
     ((x & 0x00FF000000000000ULL) >> 40) | \
     ((x & 0x0000FF0000000000ULL) >> 24) | \
     ((x & 0x000000FF00000000ULL) >>  8) | \
     ((x & 0x00000000FF000000ULL) <<  8) | \
     ((x & 0x0000000000FF0000ULL) << 24) | \
     ((x & 0x000000000000FF00ULL) << 40) | \
     ((x & 0x00000000000000FFULL) << 56))

void
GOST_Cleanup(GOST_Context *CTX)
{
    memset(CTX, 0x00, sizeof (GOST_Context));
}

void
GOST_Init(GOST_Context *CTX, const unsigned int digest_size)
{
    unsigned int i;

    memset(CTX, 0x00, sizeof(GOST_Context));
    CTX->digest_size = digest_size;

    for (i = 0; i < 8; i++)
    {
        if (digest_size == 256)
            CTX->h.QWORD[i] = 0x0101010101010101ULL;
        else
            CTX->h.QWORD[i] = 0x00ULL;
    }
}

static inline void
pad(GOST_Context *CTX)
{
    unsigned char buf[64];

    if (CTX->bufsize > 63)
        return;

    memset(&buf, 0x00, sizeof buf);
    memcpy(&buf, CTX->buffer, CTX->bufsize);

    buf[CTX->bufsize] = 0x01;
    memcpy(CTX->buffer, &buf, sizeof buf);
}

static inline void
add512(const union uint512_u *x, const union uint512_u *y, union uint512_u *r)
{
    unsigned int CF, OF;
    unsigned int i;

    CF = 0;
    for (i = 0; i < 8; i++)
    {
        r->QWORD[i] = x->QWORD[i] + y->QWORD[i];
        if ( (r->QWORD[i] < y->QWORD[i]) || 
             (r->QWORD[i] < x->QWORD[i]) )
            OF = 1;
        else
            OF = 0;

        r->QWORD[i] += CF;
        CF = OF;
    }
}

static void
g(union uint512_u *h, const union uint512_u *N, const unsigned char *m)
{
    union uint512_u Ki, data;
    unsigned int i;

    XLPS(h, N, (&data));

    /* Starting E() */
    Ki = data;
    XLPS((&Ki), ((const union uint512_u *) &m[0]), (&data));

    for (i = 0; i < 11; i++)
        ROUND(i, (&Ki), (&data));

    XLPS((&Ki), (&C[11]), (&Ki));
    X((&Ki), (&data), (&data));
    /* E() done */

    X((&data), h, (&data));
    X((&data), ((const union uint512_u *) &m[0]), h);
}

static inline void
stage2(GOST_Context *CTX, const unsigned char *data)
{
    g(&(CTX->h), &(CTX->N), data);

    add512(&(CTX->N), &buffer512, &(CTX->N));
    add512(&(CTX->Sigma), (const union uint512_u *) data, &(CTX->Sigma));
}

static inline void
stage3(GOST_Context *CTX)
{
    ALIGN(16) union uint512_u buf;

    memset(&buf, 0x00, sizeof buf);
    memcpy(&buf, &(CTX->buffer), CTX->bufsize);
    memcpy(&(CTX->buffer), &buf, sizeof uint512_u);

    memset(&buf, 0x00, sizeof buf);

    buf.QWORD[0] = CTX->bufsize << 3;

    pad(CTX);

    g(&(CTX->h), &(CTX->N), (const unsigned char *) &(CTX->buffer));

    add512(&(CTX->N), &buf, &(CTX->N));
    add512(&(CTX->Sigma), (const union uint512_u *) &CTX->buffer[0],
           &(CTX->Sigma));

    g(&(CTX->h), &buffer0, (const unsigned char *) &(CTX->N));

    g(&(CTX->h), &buffer0, (const unsigned char *) &(CTX->Sigma));
    memcpy(&(CTX->hash), &(CTX->h), sizeof uint512_u);
}

void
GOST_Update(GOST_Context *CTX, const unsigned char *data, size_t len)
{
    size_t chunksize;

    while (len > 63 && CTX->bufsize == 0)
    {
        stage2(CTX, data);

        data += 64;
        len  -= 64;
    }

    while (len)
    {
        chunksize = 64 - CTX->bufsize;
        if (chunksize > len)
            chunksize = len;

        memcpy(&CTX->buffer[CTX->bufsize], data, chunksize);

        CTX->bufsize += chunksize;
        len -= chunksize;
        data += chunksize;
        
        if (CTX->bufsize == 64)
        {
            stage2(CTX, CTX->buffer);

            CTX->bufsize = 0;
        }
    }
}

void
GOST_Final(GOST_Context *CTX, unsigned char *digest)
{
    stage3(CTX);

    CTX->bufsize = 0;

    if (CTX->digest_size == 256)
        memcpy(digest, &(CTX->hash.QWORD[4]), 32);
    else
        memcpy(digest, &(CTX->hash.QWORD[0]), 64);
}
