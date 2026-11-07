/*
 * Apple VNC encoding 1011 ("MVS") decoder. See mvs.h.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Port to C of the noVNC-ARD JavaScript decoder (MPL 2.0),
 *   https://github.com/peetinc/noVNC-ARD  (commit d699293635083c9e0c30c8f9480993865653772a)
 *   ard/decoders/mvs.js, mvs-bitstream.js, mvs-rice.js, mvs-huffman.js,
 *   mvs-idct.js, mvs-tables.js
 * The structure follows the JS closely so the two can be compared.
 *
 * Differences from the JS, all deliberate:
 *  - Everything that comes from the network is bounds checked. Where the JS
 *    leans on typed-array behaviour, the C does the same on purpose:
 *      Int8Array/Int16Array stores truncate (casts here), Int8Array reads of
 *      cache slot 65000 (one past the array) give 0 (the slot exists and is
 *      zero), writes outside an array are ignored (checked, skipped),
 *      `<<`, `>>` and `&` wrap to int32 (i32()/shl32()), while `+ - *` on
 *      JS numbers do not wrap (int64 here, which is exact for every value the
 *      IDCT can reach).
 *  - A JS `throw` (bit read past the end, bad Huffman code, bad header) is a
 *    longjmp back to mvs_decode_rect(), so state is left exactly as the JS
 *    leaves it when it throws.
 *  - Allocation sizes are capped (MVS_MAX_PIXELS).
 */
#include "mvs.h"

#include <pthread.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ tables */

#define CACHE_SIZE 65000
#define CACHE_ENTRY_Y 64
#define CACHE_ENTRY_CR 15
#define CACHE_ENTRY_CB 20
#define CACHE_ENTRY_SIZE (CACHE_ENTRY_Y + CACHE_ENTRY_CR + CACHE_ENTRY_CB) /* 99 */
#define CB 64
#define CR 128

static const uint8_t ZIGZAG[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};

static const uint8_t DEFAULT_LUMA_QUANT[64] = {
    16, 11, 11, 14, 24, 22, 24, 33, 11, 12, 11, 11, 26, 18, 19, 23,
    13, 13, 14, 24, 20, 21, 22, 28, 13, 17, 14, 21, 23, 25, 34, 34,
    17, 22, 18, 25, 31, 32, 34, 44, 24, 20, 17, 27, 35, 40, 44, 54,
    30, 35, 28, 30, 34, 44, 54, 64, 35, 30, 33, 38, 45, 55, 65, 75};

static const uint8_t DEFAULT_CHROMA_QUANT[64] = {
    19, 19, 24, 47, 76, 99, 99, 99, 19, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
    76, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99};

/* K.5 AC luminance Huffman table */
static const uint8_t AC_BITS[16] = {0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125};
static const uint8_t AC_VALUES[162] = {
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
    0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA};

static int32_t huff_max[17], huff_min[17], huff_ptr[17];
/* YCbCr -> RGB (libjpeg jdcolor.c), indexed by the chroma sample 0..255 */
static int32_t CR_R_TAB[256], CB_B_TAB[256], CR_G_TAB[256], CB_G_TAB[256];

static pthread_once_t tables_once = PTHREAD_ONCE_INIT;

static void build_tables(void) {
    for (int i = 0; i < 256; i++) {
        int32_t x = i - 128;
        CR_R_TAB[i] = (91881 * x + 32768) >> 16;
        CB_B_TAB[i] = (116130 * x + 32768) >> 16;
        CR_G_TAB[i] = -46802 * x;
        CB_G_TAB[i] = -22554 * x + 32768;
    }
    for (int i = 0; i <= 16; i++) {
        huff_max[i] = -1;
        huff_min[i] = 0;
        huff_ptr[i] = 0;
    }
    int32_t code = 0, valIdx = 0;
    for (int len = 1; len <= 16; len++) {
        int count = AC_BITS[len - 1];
        if (count == 0) {
            huff_max[len] = -1;
            code <<= 1;
            continue;
        }
        huff_min[len] = code;
        huff_ptr[len] = valIdx;
        valIdx += count;
        huff_max[len] = code + count - 1;
        code = (code + count) << 1;
    }
}

/* -------------------------------------------------------------- JS numerics */

/* ToInt32 of an exact integer */
static inline int32_t i32(int64_t v) { return (int32_t)(uint32_t)(uint64_t)v; }
/* JS `v << n` */
static inline int32_t shl32(int64_t v, int n) { return (int32_t)((uint32_t)(uint64_t)v << n); }
/* JS `v >> n` */
static inline int32_t sar32(int64_t v, int n) { return i32(v) >> n; }
/* Store into an Int16Array / Int8Array */
static inline int16_t to16(int64_t v) { return (int16_t)(uint16_t)(uint64_t)v; }
static inline int8_t to8(int64_t v) { return (int8_t)(uint8_t)(uint64_t)v; }
/* The decoder's int8() helper: ((v + 128) & 0xFF) - 128 */
static inline int int8v(int64_t v) { return (int)to8(v); }

static inline int clamp255(int v) { return v < 0 ? 0 : (v > 255 ? 255 : v); }
static inline uint32_t rgba(int r, int g, int b) {
    return (uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | 0xFF000000u;
}

/* ----------------------------------------------------------------- decoder */

struct mvs_decoder {
    uint8_t lumaQuant[64], chromaQuant[64];
    int16_t coeffs[192];
    int16_t dpcm[192];
    uint32_t tile[64]; /* 8x8 output */
    int8_t cacheEntry[CACHE_ENTRY_SIZE];
    int32_t dq[64];
    uint8_t ySp[64], cbSp[64], crSp[64];
    uint8_t solid[3], twoA[3], twoB[3];

    int8_t *cache;          /* (CACHE_SIZE + 1) * 99, slot 0 and 65000 never written */
    uint32_t cacheWriteIdx; /* most recently written slot (0 = none yet) */
    uint32_t cacheLastIdx;  /* most recently loaded slot */
    uint32_t cacheCount;    /* total inserts (saturating) */
    uint32_t *cachePixels;  /* 64 per slot, allocated on first use */
    uint32_t *cachePixelGen;
    uint32_t quantGen;

    uint32_t *fb;
    int fbW, fbH, stx, total;
    uint8_t *tThr;
    int8_t *tY;
    uint8_t *tCbValid, *tCrValid;
    int8_t *tCbDC, *tCrDC;
    uint32_t *tSeq;
    int32_t *tRef;
    int16_t *tMX, *tMY;
    uint32_t frameSeq;

    jmp_buf jb;
    int err;
    int warnings;
    int pminX, pminY, pmaxX, pmaxY; /* partial update bounds of changed tiles */
};

static void screen_free(mvs_decoder *d) {
    free(d->fb);
    free(d->tThr);
    free(d->tY);
    free(d->tCbValid);
    free(d->tCrValid);
    free(d->tCbDC);
    free(d->tCrDC);
    free(d->tSeq);
    free(d->tRef);
    free(d->tMX);
    free(d->tMY);
    d->fb = NULL;
    d->tThr = NULL; d->tY = NULL; d->tCbValid = NULL; d->tCrValid = NULL;
    d->tCbDC = NULL; d->tCrDC = NULL; d->tSeq = NULL; d->tRef = NULL; d->tMX = NULL; d->tMY = NULL;
    d->fbW = d->fbH = d->stx = d->total = 0;
}

mvs_decoder *mvs_new(void) {
    pthread_once(&tables_once, build_tables);
    mvs_decoder *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    memcpy(d->lumaQuant, DEFAULT_LUMA_QUANT, 64);
    memcpy(d->chromaQuant, DEFAULT_CHROMA_QUANT, 64);
    d->quantGen = 1;
    return d;
}

static void cache_free(mvs_decoder *d) {
    free(d->cache); free(d->cachePixels); free(d->cachePixelGen);
    d->cache = NULL; d->cachePixels = NULL; d->cachePixelGen = NULL;
    d->cacheWriteIdx = d->cacheLastIdx = d->cacheCount = 0;
}

void mvs_free(mvs_decoder *d) {
    if (!d) return;
    screen_free(d);
    cache_free(d);
    free(d);
}

void mvs_reset(mvs_decoder *d) {
    screen_free(d);
    cache_free(d);
    d->frameSeq = 0;
    memset(d->dpcm, 0, sizeof d->dpcm);
}

/* (Re)allocate screen state when the framebuffer size changes. */
static int ensure_screen(mvs_decoder *d, int w, int h) {
    if (w == d->fbW && h == d->fbH) return MVS_OK;
    screen_free(d);
    if (w < 0 || h < 0 || (int64_t)w * h > MVS_MAX_PIXELS) return MVS_ERR_SIZE;
    size_t px = (size_t)w * h;
    int stx = (w + 7) / 8, sty = (h + 7) / 8;
    size_t total = (size_t)stx * sty;
    d->fbW = w; d->fbH = h; d->stx = stx; d->total = (int)total;
    d->fb = calloc(px ? px : 1, 4);
    d->tThr = calloc(total ? total : 1, 1);
    d->tY = calloc(total ? total : 1, 64);
    d->tCbValid = calloc(total ? total : 1, 1);
    d->tCrValid = calloc(total ? total : 1, 1);
    d->tCbDC = calloc(total ? total : 1, 1);
    d->tCrDC = calloc(total ? total : 1, 1);
    d->tSeq = calloc(total ? total : 1, 4);
    d->tRef = calloc(total ? total : 1, 4);
    d->tMX = calloc(total ? total : 1, 2);
    d->tMY = calloc(total ? total : 1, 2);
    if (!d->fb || !d->tThr || !d->tY || !d->tCbValid || !d->tCrValid || !d->tCbDC || !d->tCrDC ||
        !d->tSeq || !d->tRef || !d->tMX || !d->tMY) {
        screen_free(d);
        return MVS_ERR_NOMEM;
    }
    for (size_t i = 0; i < total; i++) d->tRef[i] = -1;
    return MVS_OK;
}

/* --------------------------------------------------------------- bitstream */

typedef struct {
    const uint8_t *p;
    size_t len, bytePos;
    int bitPos; /* 0 = MSB */
    mvs_decoder *d;
} bits_t;

static void bits_init(bits_t *b, mvs_decoder *d, const uint8_t *p, size_t len) {
    b->p = p; b->len = len; b->bytePos = 0; b->bitPos = 0; b->d = d;
}

static _Noreturn void fail(mvs_decoder *d, int code) {
    d->err = code;
    longjmp(d->jb, 1);
}

static int rbit(bits_t *b) {
    if (b->bytePos >= b->len) fail(b->d, MVS_ERR_TRUNC);
    int bit = (b->p[b->bytePos] >> (7 - b->bitPos)) & 1;
    if (++b->bitPos > 7) { b->bitPos = 0; b->bytePos++; }
    return bit;
}

static int rbits(bits_t *b, int n) { /* n <= 16 */
    int v = 0;
    for (int i = 0; i < n; i++) v = (v << 1) | rbit(b);
    return v;
}

/* ------------------------------------------------------------- Rice / Huffman */

static int64_t leading_ones(bits_t *b) {
    int64_t n = 0;
    while (rbit(b) == 1) n++;
    return n;
}

/* `(N << 3) | bits` in JS: N goes through ToInt32 and wraps */
static inline int64_t shl3or(int64_t n, int bits) { return shl32(n, 3) | bits; }

static int64_t decode_dc_rice(bits_t *b) {
    int64_t n = leading_ones(b), mag;
    if (n == 0) {
        if (rbit(b) == 0) return 0;
        return rbit(b) ? -1 : 1;
    }
    if (n == 1) mag = 2 + rbits(b, 1);
    else if (n == 2) mag = 4 + rbits(b, 2);
    else mag = shl3or(n, rbits(b, 3)) - 16;
    return rbit(b) ? -mag : mag;
}

static int64_t ac_rice_standard(bits_t *b) {
    int64_t n = leading_ones(b), mag;
    if (n == 0) mag = 2 + rbits(b, 1);
    else if (n == 1) mag = 4 + rbits(b, 2);
    else mag = shl3or(n, rbits(b, 3)) - 8;
    return rbit(b) ? -mag : mag;
}

static int64_t ac_rice_near_dc(bits_t *b) {
    int64_t n = leading_ones(b), mag;
    if (n <= 3) mag = 2 + n * 4 + rbits(b, 2);
    else mag = 18 + (n - 4) * 8 + rbits(b, 3);
    return rbit(b) ? -mag : mag;
}

static int quant_step(int pos, int threshold) {
    if (pos <= 5) {
        if (threshold > 14) return 2;
        if (pos < threshold) return 8;
        return 16;
    }
    if (threshold > 14 && pos < threshold) return 2;
    if (threshold > 14) return 8;
    if (pos < threshold) return 8;
    return 16;
}

typedef struct { int64_t value; int eob; int skip; } ac_t;

static void decode_ac(bits_t *b, int pos, int threshold, ac_t *r) {
    r->value = 0; r->eob = 0; r->skip = 0;
    if (rbit(b) == 1) {
        int64_t raw = pos <= 5 ? ac_rice_near_dc(b) : ac_rice_standard(b);
        r->value = raw * quant_step(pos, threshold);
        return;
    }
    switch (rbits(b, 2)) {
    case 0: break;
    case 1:
        if (rbit(b) == 0) {
            r->eob = 1;
        } else {
            int ext = rbits(b, 2);
            if (ext < 3) {
                r->skip = ext + 3;
            } else {
                int run = 6;
                for (;;) {
                    int chunk = rbits(b, 3);
                    run += chunk;
                    if (chunk < 7) break;
                    if (run + pos >= 64) break; /* a run never extends past the block */
                }
                r->skip = run;
            }
        }
        break;
    case 2: r->value = quant_step(pos, threshold); break;
    case 3: r->value = -quant_step(pos, threshold); break;
    }
}

static int huff_symbol(bits_t *b) {
    int32_t code = 0;
    for (int len = 1; len <= 16; len++) {
        code = (code << 1) | rbit(b);
        if (huff_max[len] >= 0 && code <= huff_max[len]) {
            int idx = huff_ptr[len] + (code - huff_min[len]);
            if (idx < 0 || idx >= 162) fail(b->d, MVS_ERR_DATA); /* cannot happen with this table */
            return AC_VALUES[idx];
        }
    }
    fail(b->d, MVS_ERR_DATA); /* 16 bits exhausted */
}

/* coeffs written at offset + position; limit = number of AC positions coded */
static void huffman_ac(bits_t *b, int16_t *coeffs, int offset, int limit) {
    int k = 0;
    while (k < limit) {
        int symbol = huff_symbol(b);
        int run = symbol >> 4, vbits = symbol & 15;
        if (vbits == 0) {
            if (run != 15) break; /* EOB */
            k += 16;
            continue;
        }
        k += run;
        int raw = rbits(b, vbits);
        int value = raw < (1 << (vbits - 1)) ? raw - (1 << vbits) + 1 : raw;
        int at = k + 1 < 63 ? k + 1 : 63; /* positions past 63 land on 63 */
        coeffs[offset + at] = (int16_t)value;
        k++;
    }
}

/* -------------------------------------------------------------------- IDCT */

#define CONST_BITS 13
#define PASS1_BITS 2
#define F_0_298631336 2446
#define F_0_390180644 3196
#define F_0_541196100 4433
#define F_0_765366865 6270
#define F_0_899976223 7373
#define F_1_175875602 9633
#define F_1_501321110 12299
#define F_1_847759065 15137
#define F_1_961570560 16069
#define F_2_053119869 16819
#define F_2_562915447 20995
#define F_3_072711026 25172

static inline int range_limit(int32_t v) {
    v &= 0x3FF;
    if (v < 128) return v + 128;
    if (v < 512) return 255;
    if (v < 896) return 0;
    return v - 896;
}

static int idct_flat(int32_t dc) {
    return range_limit(sar32((int64_t)shl32(dc, PASS1_BITS) + (1 << (PASS1_BITS + 2)), PASS1_BITS + 3));
}

/* The odd part shared by both passes. Takes the four odd inputs, returns
 * tmp0..tmp3 (already multiplied and combined). */
static inline void idct_odd(int64_t in0, int64_t in1, int64_t in2, int64_t in3, int64_t *o0,
                            int64_t *o1, int64_t *o2, int64_t *o3) {
    int64_t tmp0 = in0, tmp1 = in1, tmp2 = in2, tmp3 = in3;
    int64_t z1 = tmp0 + tmp3, z2 = tmp1 + tmp2, z3 = tmp0 + tmp2, z4 = tmp1 + tmp3;
    int64_t z5 = (z3 + z4) * F_1_175875602;
    tmp0 *= F_0_298631336;
    tmp1 *= F_2_053119869;
    tmp2 *= F_3_072711026;
    tmp3 *= F_1_501321110;
    z1 *= -F_0_899976223;
    z2 *= -F_2_562915447;
    z3 = z3 * -F_1_961570560 + z5;
    z4 = z4 * -F_0_390180644 + z5;
    *o0 = tmp0 + z1 + z3;
    *o1 = tmp1 + z2 + z4;
    *o2 = tmp2 + z2 + z3;
    *o3 = tmp3 + z1 + z4;
}

/* jpeg_idct_islow; block = 64 dequantized coefficients in natural order */
static void idct8x8(const int32_t *block, uint8_t *out) {
    int32_t ws[64];
    for (int c = 0; c < 8; c++) {
        if (block[c + 8] == 0 && block[c + 16] == 0 && block[c + 24] == 0 && block[c + 32] == 0 &&
            block[c + 40] == 0 && block[c + 48] == 0 && block[c + 56] == 0) {
            int32_t dc = shl32(block[c], PASS1_BITS);
            for (int r = 0; r < 64; r += 8) ws[c + r] = dc;
            continue;
        }
        int64_t z2 = block[c + 16], z3 = block[c + 48];
        int64_t z1 = (z2 + z3) * F_0_541196100;
        int64_t tmp2 = z1 - z3 * F_1_847759065;
        int64_t tmp3 = z1 + z2 * F_0_765366865;
        z2 = block[c];
        z3 = block[c + 32];
        int64_t tmp0 = shl32(z2 + z3, CONST_BITS);
        int64_t tmp1 = shl32(z2 - z3, CONST_BITS);
        int64_t t10 = tmp0 + tmp3, t13 = tmp0 - tmp3, t11 = tmp1 + tmp2, t12 = tmp1 - tmp2;
        int64_t o0, o1, o2, o3;
        idct_odd(block[c + 56], block[c + 40], block[c + 24], block[c + 8], &o0, &o1, &o2, &o3);
        const int shift = CONST_BITS - PASS1_BITS, round = 1 << (shift - 1);
        ws[c] = sar32(t10 + o3 + round, shift);
        ws[c + 56] = sar32(t10 - o3 + round, shift);
        ws[c + 8] = sar32(t11 + o2 + round, shift);
        ws[c + 48] = sar32(t11 - o2 + round, shift);
        ws[c + 16] = sar32(t12 + o1 + round, shift);
        ws[c + 40] = sar32(t12 - o1 + round, shift);
        ws[c + 24] = sar32(t13 + o0 + round, shift);
        ws[c + 32] = sar32(t13 - o0 + round, shift);
    }
    for (int r = 0; r < 64; r += 8) {
        int64_t z2 = ws[r + 2], z3 = ws[r + 6];
        int64_t z1 = (z2 + z3) * F_0_541196100;
        int64_t tmp2 = z1 - z3 * F_1_847759065;
        int64_t tmp3 = z1 + z2 * F_0_765366865;
        int64_t tmp0 = shl32((int64_t)ws[r] + ws[r + 4], CONST_BITS);
        int64_t tmp1 = shl32((int64_t)ws[r] - ws[r + 4], CONST_BITS);
        int64_t t10 = tmp0 + tmp3, t13 = tmp0 - tmp3, t11 = tmp1 + tmp2, t12 = tmp1 - tmp2;
        int64_t o0, o1, o2, o3;
        idct_odd(ws[r + 7], ws[r + 5], ws[r + 3], ws[r + 1], &o0, &o1, &o2, &o3);
        const int shift = CONST_BITS + PASS1_BITS + 3;
        const int64_t round = (int64_t)1 << (shift - 1);
        out[r] = (uint8_t)range_limit(sar32(t10 + o3 + round, shift));
        out[r + 7] = (uint8_t)range_limit(sar32(t10 - o3 + round, shift));
        out[r + 1] = (uint8_t)range_limit(sar32(t11 + o2 + round, shift));
        out[r + 6] = (uint8_t)range_limit(sar32(t11 - o2 + round, shift));
        out[r + 2] = (uint8_t)range_limit(sar32(t12 + o1 + round, shift));
        out[r + 5] = (uint8_t)range_limit(sar32(t12 - o1 + round, shift));
        out[r + 3] = (uint8_t)range_limit(sar32(t13 + o0 + round, shift));
        out[r + 4] = (uint8_t)range_limit(sar32(t13 - o0 + round, shift));
    }
}

/* ------------------------------------------------------- dequant and render */

/* One plane of coeffs into `out`. A DC-only plane is a flat value, returned
 * with `out` untouched; otherwise returns -1. */
static int transform_plane(mvs_decoder *d, int plane, const uint8_t *quant, uint8_t *out) {
    int ac = 0;
    for (int i = 1; i < 64; i++) {
        int n = ZIGZAG[i];
        int value = d->coeffs[plane + i];
        ac |= value;
        d->dq[n] = value * quant[n];
    }
    int32_t dc = d->coeffs[plane] * quant[0];
    if (ac == 0) return idct_flat(dc);
    d->dq[0] = dc;
    idct8x8(d->dq, out);
    return -1;
}

static void dequant_and_render(mvs_decoder *d) {
    int yFlat = transform_plane(d, 0, d->lumaQuant, d->ySp);
    if (yFlat >= 0) memset(d->ySp, yFlat, 64);
    int cbFlat = transform_plane(d, CB, d->chromaQuant, d->cbSp);
    int crFlat = transform_plane(d, CR, d->chromaQuant, d->crSp);

    if (cbFlat >= 0 && crFlat >= 0) {
        int rAdd = CR_R_TAB[crFlat];
        int gAdd = (CB_G_TAB[cbFlat] + CR_G_TAB[crFlat]) >> 16;
        int bAdd = CB_B_TAB[cbFlat];
        for (int i = 0; i < 64; i++) {
            int y = d->ySp[i];
            d->tile[i] = rgba(clamp255(y + rAdd), clamp255(y + gAdd), clamp255(y + bAdd));
        }
        return;
    }
    if (cbFlat >= 0) memset(d->cbSp, cbFlat, 64);
    if (crFlat >= 0) memset(d->crSp, crFlat, 64);
    for (int i = 0; i < 64; i++) {
        int y = d->ySp[i], cb = d->cbSp[i], cr = d->crSp[i];
        d->tile[i] = rgba(clamp255(y + CR_R_TAB[cr]),
                          clamp255(y + ((CB_G_TAB[cb] + CR_G_TAB[cr]) >> 16)),
                          clamp255(y + CB_B_TAB[cb]));
    }
}

/* ------------------------------------------------------------- framebuffer */

static void put_tile(mvs_decoder *d, int tx, int ty, int tw, int th) {
    /* callers keep the tile inside the framebuffer; check anyway */
    if (tx < 0 || ty < 0 || tw <= 0 || th <= 0 || tx + tw > d->fbW || ty + th > d->fbH) return;
    uint32_t *dst = d->fb + (size_t)ty * d->fbW + tx;
    for (int row = 0; row < th; row++, dst += d->fbW) memcpy(dst, d->tile + row * 8, (size_t)tw * 4);
}

/* A source outside the framebuffer leaves the destination as it is. */
static void copy_tile(mvs_decoder *d, int sx, int sy, int dx, int dy, int tw, int th) {
    if (sx < 0 || sy < 0 || sx >= d->fbW || sy >= d->fbH) return;
    if (dx < 0 || dy < 0 || tw <= 0 || th <= 0 || dx + tw > d->fbW || dy + th > d->fbH) return;
    int rowPx = tw < d->fbW - sx ? tw : d->fbW - sx;
    const uint32_t *src = d->fb + (size_t)sy * d->fbW + sx;
    uint32_t *dst = d->fb + (size_t)dy * d->fbW + dx;
    for (int row = 0; row < th && sy + row < d->fbH; row++, src += d->fbW, dst += d->fbW)
        memmove(dst, src, (size_t)rowPx * 4);
}

/* ------------------------------------------------------------- tile types */

static void read_ycbcr20(bits_t *b, uint8_t *rgb) {
    int y = rbits(b, 8), cb = rbits(b, 6) << 2, cr = rbits(b, 6) << 2;
    rgb[0] = (uint8_t)clamp255(y + CR_R_TAB[cr]);
    rgb[1] = (uint8_t)clamp255(y + ((CB_G_TAB[cb] + CR_G_TAB[cr]) >> 16));
    rgb[2] = (uint8_t)clamp255(y + CB_B_TAB[cb]);
}

static void decode_two_color_bw(mvs_decoder *d, bits_t *b) {
    int rowSel = rbits(b, 8);
    for (int row = 0; row < 8; row++) {
        if ((rowSel >> (7 - row)) & 1) {
            for (int col = 0; col < 8; col++) d->tile[row * 8 + col] = 0xFFFFFFFFu;
        } else {
            int bitsv = rbits(b, 8);
            for (int col = 0; col < 8; col++)
                d->tile[row * 8 + col] = ((bitsv >> (7 - col)) & 1) ? 0xFFFFFFFFu : 0xFF000000u;
        }
    }
}

static void render_two_color(mvs_decoder *d, bits_t *b, const uint8_t *A, const uint8_t *B) {
    int rowSel = rbits(b, 8);
    for (int row = 0; row < 8; row++) {
        int bitsv = ((rowSel >> (7 - row)) & 1) ? 0xFF : rbits(b, 8);
        for (int col = 0; col < 8; col++) {
            const uint8_t *c = ((bitsv >> (7 - col)) & 1) ? A : B;
            d->tile[row * 8 + col] = rgba(c[0], c[1], c[2]);
        }
    }
}

static void decode_solid_or_two_color(mvs_decoder *d, bits_t *b) {
    int two = rbit(b), reuse = rbit(b);
    if (!two) {
        if (!reuse) read_ycbcr20(b, d->solid);
        uint32_t px = rgba(d->solid[0], d->solid[1], d->solid[2]);
        for (int i = 0; i < 64; i++) d->tile[i] = px;
    } else {
        if (!reuse) {
            read_ycbcr20(b, d->twoA);
            read_ycbcr20(b, d->twoB);
        }
        render_two_color(d, b, d->twoA, d->twoB);
    }
}

/* ------------------------------------------------------------------- cache */

/* Renders slot idx into d->tile. False, leaving the tile alone, if never written. */
static int load_cache_and_render(mvs_decoder *d, uint32_t idx) {
    if (idx == 0 || idx > CACHE_SIZE || idx > d->cacheCount) {
        d->warnings++;
        return 0;
    }
    if (!d->cachePixels) {
        d->cachePixels = calloc((size_t)(CACHE_SIZE + 1) * 64, 4);
        d->cachePixelGen = calloc(CACHE_SIZE + 1, 4);
        if (!d->cachePixels || !d->cachePixelGen) {
            free(d->cachePixels); free(d->cachePixelGen);
            d->cachePixels = NULL; d->cachePixelGen = NULL;
            fail(d, MVS_ERR_NOMEM);
        }
    }
    uint32_t *px = d->cachePixels + (size_t)idx * 64;
    if (d->cachePixelGen[idx] == d->quantGen) {
        memcpy(d->tile, px, 64 * 4);
    } else {
        /* idx <= cacheCount implies the cache exists; slot 65000 reads as zeros like the JS */
        const int8_t *e = d->cache + (size_t)idx * CACHE_ENTRY_SIZE;
        memset(d->coeffs, 0, sizeof d->coeffs);
        for (int i = 0; i < CACHE_ENTRY_Y; i++) d->coeffs[i] = e[i];
        for (int i = 0; i < CACHE_ENTRY_CR; i++) d->coeffs[CR + i] = e[CACHE_ENTRY_Y + i];
        for (int i = 0; i < CACHE_ENTRY_CB; i++) d->coeffs[CB + i] = e[CACHE_ENTRY_Y + CACHE_ENTRY_CR + i];
        dequant_and_render(d);
        memcpy(px, d->tile, 64 * 4);
        d->cachePixelGen[idx] = d->quantGen;
    }
    d->cacheLastIdx = idx;
    return 1;
}

/* ------------------------------------------------------------ full update */

static void copy_tile_desc(mvs_decoder *d, int from, int to) {
    d->tThr[to] = d->tThr[from];
    memmove(d->tY + (size_t)to * 64, d->tY + (size_t)from * 64, 64);
    d->tCbValid[to] = d->tCbValid[from];
    d->tCbDC[to] = d->tCbDC[from];
    d->tCrValid[to] = d->tCrValid[from];
    d->tCrDC[to] = d->tCrDC[from];
    d->tSeq[to] = d->tSeq[from];
    d->tRef[to] = d->tRef[from];
    d->tMX[to] = d->tMX[from];
    d->tMY[to] = d->tMY[from];
}

static void decode_dct(mvs_decoder *d, bits_t *b, int thr1, int thr2, int screenIdx, int prevDct) {
    int16_t *coeffs = d->coeffs, *state = d->dpcm;
    memset(coeffs, 0, sizeof d->coeffs);

    if (rbit(b)) {
        /* repeat of the previous DCT tile: same coefficients, descriptor inherited */
        if (prevDct < 0) {
            d->warnings++;
        } else {
            for (int i = 0; i < 64; i++) coeffs[i] = state[i];
            coeffs[CB] = state[CB];
            coeffs[CR] = state[CR];
            copy_tile_desc(d, prevDct, screenIdx);
        }
    } else {
        int dcMode = rbit(b);
        int threshold = rbit(b) ? thr2 : thr1;
        if (dcMode == 0) {
            int64_t cbRice = decode_dc_rice(b);
            int cbHalf = (state[CB] + (state[CB] < 0 ? 1 : 0)) >> 1;
            coeffs[CB] = to16((cbHalf - cbRice) * 2);
            int64_t crRice = decode_dc_rice(b);
            int crHalf = (state[CR] + (state[CR] < 0 ? 1 : 0)) >> 1;
            coeffs[CR] = to16((crHalf - crRice) * 2);
        } else {
            coeffs[CB] = state[CB];
            coeffs[CR] = state[CR];
        }
        coeffs[0] = to16(state[0] - decode_dc_rice(b));

        int pos = 1;
        ac_t ac;
        while (pos < 64) {
            decode_ac(b, pos, threshold, &ac);
            if (ac.eob) break;
            if (ac.skip > 0) pos += ac.skip;
            else { coeffs[pos] = to16(ac.value); pos++; }
        }

        /* the descriptor keeps the int8-truncated coefficients */
        d->tThr[screenIdx] = (uint8_t)threshold;
        int8_t *dy = d->tY + (size_t)screenIdx * 64;
        for (int i = 0; i < 64; i++) dy[i] = to8(coeffs[i]);
        d->tCbValid[screenIdx] = 1;
        d->tCbDC[screenIdx] = to8(coeffs[CB]);
        d->tCrValid[screenIdx] = 1;
        d->tCrDC[screenIdx] = to8(coeffs[CR]);
    }
    memcpy(state, coeffs, sizeof d->coeffs);
    dequant_and_render(d);
}

static void run_full(mvs_decoder *d, const uint8_t *data, size_t len, int x, int y, int w, int h) {
    if (len < 6) fail(d, MVS_ERR_DATA); /* the JS reads offset 0 from missing bytes and rejects it */
    int thr1 = data[1], thr2 = data[2];
    int tilesX = (w + 7) / 8, tilesY = (h + 7) / 8;
    int64_t totalTiles = (int64_t)tilesX * tilesY;
    size_t bodyOffset = ((size_t)data[3] << 16) | ((size_t)data[4] << 8) | data[5];
    if (bodyOffset < 6 || bodyOffset > len) fail(d, MVS_ERR_DATA);

    bits_t hb, bb;
    bits_init(&hb, d, data + 6, bodyOffset - 6);
    bits_init(&bb, d, data + bodyOffset, len - bodyOffset);
    rbit(&hb); /* one bit the Apple viewer ignores */

    d->frameSeq++;
    memset(d->dpcm, 0, sizeof d->dpcm);
    memset(d->solid, 0, 3);
    memset(d->twoA, 255, 3);
    d->twoB[0] = 181; d->twoB[1] = 213; d->twoB[2] = 254;

    int prevDct = -1, prevTX = x, prevTY = y;
    int64_t tileIdx = 0;
    while (tileIdx < totalTiles) {
        int tileType = rbits(&hb, 3);
        int64_t count = 1;
        if (rbit(&hb)) {
            int v4 = rbits(&hb, 4);
            if (v4 < 15) {
                count = v4 + 2;
            } else {
                int b1 = rbits(&hb, 8), varint;
                if ((b1 & 0x80) == 0) {
                    varint = b1;
                } else {
                    int b2 = rbits(&hb, 8);
                    if ((b2 & 0x80) == 0) {
                        varint = (b2 << 7) | (b1 & 0x7F);
                    } else {
                        int b3 = rbits(&hb, 8);
                        varint = (b3 << 14) | ((b2 & 0x7F) << 7) | (b1 & 0x7F);
                    }
                }
                count = varint + 17;
            }
        }
        for (; count > 0 && tileIdx < totalTiles; count--, tileIdx++) {
            int col = (int)(tileIdx % tilesX), row = (int)(tileIdx / tilesX);
            int tx = x + col * 8, ty = y + row * 8;
            int tw = x + w - tx < 8 ? x + w - tx : 8;
            int th = y + h - ty < 8 ? y + h - ty : 8;
            int screenIdx = (ty >> 3) * d->stx + (tx >> 3);
            /* rect is inside the framebuffer, so screenIdx is inside the grid */
            if (screenIdx < 0 || screenIdx >= d->total) fail(d, MVS_ERR_DATA);

            d->tSeq[screenIdx] = d->frameSeq;
            d->tRef[screenIdx] = -1;
            int rendered = 1;
            switch (tileType) {
            case 0: for (int i = 0; i < 64; i++) d->tile[i] = 0xFFFFFFFFu; break;
            case 1:
                d->tRef[screenIdx] = screenIdx - 1;
                d->tMX[screenIdx] = to16(prevTX);
                d->tMY[screenIdx] = to16(prevTY);
                copy_tile(d, prevTX, prevTY, tx, ty, tw, th);
                rendered = 0;
                break;
            case 2:
                d->tRef[screenIdx] = screenIdx - d->stx;
                d->tMX[screenIdx] = to16(tx);
                d->tMY[screenIdx] = to16(ty - 8);
                copy_tile(d, tx, ty - 8, tx, ty, tw, th);
                rendered = 0;
                break;
            case 3: decode_two_color_bw(d, &bb); break;
            case 4: decode_solid_or_two_color(d, &bb); break;
            case 5:
                decode_dct(d, &bb, thr1, thr2, screenIdx, prevDct);
                prevDct = screenIdx;
                break;
            case 6: rendered = load_cache_and_render(d, (uint32_t)rbits(&bb, 16)); break;
            case 7: rendered = load_cache_and_render(d, (d->cacheLastIdx + 1) & 0xFFFF); break;
            }
            if (rendered) put_tile(d, tx, ty, tw, th);
            prevTX = tx;
            prevTY = ty;
        }
    }
    /* both bitstreams end with 'm' (0x6d), not byte-aligned */
    if (rbits(&hb, 8) != 0x6d) d->warnings++;
    if (rbits(&bb, 8) != 0x6d) d->warnings++;
}

/* ---------------------------------------------------------- partial update */

static int chroma_dc_delta(bits_t *b, int baseline) {
    int bit = rbit(b);
    if (baseline != 0) return int8v(baseline >= 0 ? baseline + bit : baseline - bit);
    if (bit) return rbit(b) ? -1 : 1;
    return 0;
}

static void decode_partial_dct(mvs_decoder *d, bits_t *b, int screenIdx, int crLimit, int cbLimit) {
    if (!d->tCrValid[screenIdx] || !d->tCbValid[screenIdx]) fail(d, MVS_ERR_DATA);
    int16_t *coeffs = d->coeffs;
    int8_t *entry = d->cacheEntry;
    const int8_t *descY = d->tY;
    memset(coeffs, 0, sizeof d->coeffs);
    memset(entry, 0, CACHE_ENTRY_SIZE);

    int threshold = d->tThr[screenIdx];
    size_t descBase = (size_t)screenIdx * 64, descEnd = descBase + 64;
    coeffs[0] = descY[descBase];
    entry[0] = descY[descBase];

    int acCount = rbits(b, 6);
    int end = acCount + 1;
    size_t descPos = descBase + 1;
    int entryPos = 1;

    int phase1End = end < threshold ? end : threshold;
    if (threshold < 15) {
        for (int pos = 1; pos < phase1End; pos++) {
            int prev = descPos < descEnd ? descY[descPos] : 0;
            descPos++;
            int value;
            if (prev == 0) {
                value = int8v(decode_dc_rice(b));
            } else {
                int delta = rbits(b, 3);
                value = int8v(prev >= 0 ? prev + delta : prev - delta);
            }
            coeffs[pos] = (int16_t)value;
            entry[entryPos++] = (int8_t)value;
        }
    } else {
        for (int pos = 1; pos < phase1End; pos++) {
            int prev = descPos < descEnd ? descY[descPos] : 0;
            descPos++;
            int value = 0;
            if (prev == 0) {
                if (rbit(b)) value = rbit(b) ? -1 : 1;
            } else {
                int delta = rbit(b);
                value = int8v(prev >= 0 ? prev + delta : prev - delta);
            }
            coeffs[pos] = (int16_t)value;
            entry[entryPos++] = (int8_t)value;
        }
    }
    if (acCount >= threshold) {
        int deltaBits = threshold < 15 ? 4 : 3;
        for (int pos = threshold; pos < end; pos++) {
            int prev = descPos < descEnd ? descY[descPos] : 0;
            descPos++;
            int value;
            if (prev == 0) {
                value = int8v(decode_dc_rice(b));
            } else {
                int delta = rbits(b, deltaBits);
                value = int8v(prev >= 0 ? prev + delta : prev - delta);
            }
            coeffs[pos] = (int16_t)value;
            entry[entryPos++] = (int8_t)value;
        }
    }

    coeffs[CR] = (int16_t)chroma_dc_delta(b, d->tCrDC[screenIdx]);
    huffman_ac(b, coeffs, CR, crLimit);
    for (int i = 0; i < CACHE_ENTRY_CR; i++) entry[CACHE_ENTRY_Y + i] = to8(coeffs[CR + i]);
    coeffs[CB] = (int16_t)chroma_dc_delta(b, d->tCbDC[screenIdx]);
    huffman_ac(b, coeffs, CB, cbLimit);
    for (int i = 0; i < CACHE_ENTRY_CB; i++) entry[CACHE_ENTRY_Y + CACHE_ENTRY_CR + i] = to8(coeffs[CB + i]);

    dequant_and_render(d);

    /* Only partial DCT tiles enter the cache. The descriptor is left alone. */
    if (!d->cache) {
        d->cache = calloc((size_t)(CACHE_SIZE + 1), CACHE_ENTRY_SIZE);
        if (!d->cache) fail(d, MVS_ERR_NOMEM);
    }
    d->cacheWriteIdx++;
    if (d->cacheWriteIdx == CACHE_SIZE) d->cacheWriteIdx = 1;
    if (d->cacheCount != UINT32_MAX) d->cacheCount++;
    memcpy(d->cache + (size_t)d->cacheWriteIdx * CACHE_ENTRY_SIZE, entry, CACHE_ENTRY_SIZE);
    if (d->cachePixelGen) d->cachePixelGen[d->cacheWriteIdx] = 0;
}

static void run_partial(mvs_decoder *d, const uint8_t *data, size_t len, int x, int y, int w, int h) {
    if (len < 3) fail(d, MVS_ERR_TRUNC); /* the JS has no bits to read: its first read throws */
    int crLimit = data[1] < 64 ? data[1] : 64;
    int cbLimit = data[2] < 64 ? data[2] : 64;
    int tilesX = (w + 7) / 8, tilesY = (h + 7) / 8;
    int64_t totalTiles = (int64_t)tilesX * tilesY;
    bits_t bs;
    bits_init(&bs, d, data + 3, len - 3);

    for (int64_t tileIdx = 0; tileIdx < totalTiles; tileIdx++) {
        int col = (int)(tileIdx % tilesX), row = (int)(tileIdx / tilesX);
        int tx = x + col * 8, ty = y + row * 8;
        int tw = x + w - tx < 8 ? x + w - tx : 8;
        int th = y + h - ty < 8 ? y + h - ty : 8;
        int screenIdx = (ty >> 3) * d->stx + (tx >> 3);
        if (screenIdx < 0 || screenIdx >= d->total) fail(d, MVS_ERR_DATA);
        int changed = 0;

        switch (rbits(&bs, 2)) {
        case 0: break;
        case 1:
            decode_partial_dct(d, &bs, screenIdx, crLimit, cbLimit);
            put_tile(d, tx, ty, tw, th);
            changed = 1;
            break;
        case 2: {
            int32_t ref = d->tRef[screenIdx];
            if (ref >= 0 && ref < d->total && d->tSeq[screenIdx] == d->tSeq[ref]) {
                copy_tile(d, d->tMX[screenIdx], d->tMY[screenIdx], tx, ty, tw, th);
                changed = 1;
            }
            break;
        }
        case 3: {
            uint32_t idx = rbit(&bs) ? (d->cacheLastIdx + 1) & 0xFFFF : (uint32_t)rbits(&bs, 16);
            if (load_cache_and_render(d, idx)) {
                put_tile(d, tx, ty, tw, th);
                changed = 1;
            }
            break;
        }
        }
        if (changed) {
            if (tx < d->pminX) d->pminX = tx;
            if (ty < d->pminY) d->pminY = ty;
            if (tx + tw > d->pmaxX) d->pmaxX = tx + tw;
            if (ty + th > d->pmaxY) d->pmaxY = ty + th;
        }
    }
    /* ends with "mvs", not byte-aligned */
    int m = rbits(&bs, 8), v = rbits(&bs, 8), s = rbits(&bs, 8);
    if (m != 0x6d || v != 0x76 || s != 0x73) d->warnings++;
}

/* ------------------------------------------------------------------ public */

int mvs_decode_rect(mvs_decoder *d, int fbw, int fbh, int x, int y, int w, int h,
                    const uint8_t *data, size_t len, mvs_result *res) {
    mvs_result local;
    if (!res) res = &local;
    res->x = res->y = res->w = res->h = 0;
    res->warnings = 0;
    d->warnings = 0;
    d->err = MVS_OK;

    int rc = MVS_OK;
    if (len > MVS_MAX_BODY || (len > 0 && !data)) return MVS_ERR_SIZE;
    if (x < 0 || y < 0 || w < 0 || h < 0 || fbw < 0 || fbh < 0) return MVS_ERR_RECT;
    if ((rc = ensure_screen(d, fbw, fbh)) != MVS_OK) return rc;
    if (len == 0) return MVS_ERR_TYPE;

    int type = data[0];
    if (type != 0x02 && ((int64_t)x + w > d->fbW || (int64_t)y + h > d->fbH)) {
        res->warnings = 1;
        return MVS_ERR_RECT;
    }

    switch (type) {
    case 0x02:
        if (len != 129) { rc = MVS_ERR_QUANT; break; }
        memcpy(d->lumaQuant, data + 1, 64);
        memcpy(d->chromaQuant, data + 65, 64);
        d->quantGen++;
        break;
    case 0x00:
        if (setjmp(d->jb) == 0) run_full(d, data, len, x, y, w, h);
        else rc = d->err;
        /* drawn even after an error: the tiles done so far are in the framebuffer */
        res->x = x; res->y = y; res->w = w; res->h = h;
        break;
    case 0x01:
        d->pminX = d->pminY = INT32_MAX;
        d->pmaxX = d->pmaxY = -1;
        if (setjmp(d->jb) == 0) run_partial(d, data, len, x, y, w, h);
        else rc = d->err;
        if (d->pmaxX > d->pminX) {
            res->x = d->pminX; res->y = d->pminY;
            res->w = d->pmaxX - d->pminX; res->h = d->pmaxY - d->pminY;
        }
        break;
    default:
        rc = MVS_ERR_TYPE;
        break;
    }
    res->warnings = d->warnings;
    return rc;
}

const uint32_t *mvs_pixels(const mvs_decoder *d, int *width, int *height) {
    if (width) *width = d->fbW;
    if (height) *height = d->fbH;
    return d->fb;
}

int mvs_blit(const mvs_decoder *d, int x, int y, int w, int h, void *dst, size_t stride, int bpp,
             int rshift, int gshift, int bshift, int rmax, int gmax, int bmax) {
    if (!d->fb || (bpp != 16 && bpp != 32) || !dst) return -1;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > d->fbW) w = d->fbW - x;
    if (y + h > d->fbH) h = d->fbH - y;
    if (w <= 0 || h <= 0) return 0;
    uint32_t lr[256], lg[256], lb[256];
    for (int v = 0; v < 256; v++) {
        lr[v] = (uint32_t)((v * rmax + 127) / 255) << rshift;
        lg[v] = (uint32_t)((v * gmax + 127) / 255) << gshift;
        lb[v] = (uint32_t)((v * bmax + 127) / 255) << bshift;
    }
    for (int row = 0; row < h; row++) {
        const uint32_t *s = d->fb + (size_t)(y + row) * d->fbW + x;
        uint8_t *line = (uint8_t *)dst + (size_t)(y + row) * stride + (size_t)x * (bpp / 8);
        if (bpp == 16) {
            uint16_t *o = (uint16_t *)line;
            for (int i = 0; i < w; i++) {
                uint32_t p = s[i];
                o[i] = (uint16_t)(lr[p & 255] | lg[(p >> 8) & 255] | lb[(p >> 16) & 255]);
            }
        } else {
            uint32_t *o = (uint32_t *)line;
            for (int i = 0; i < w; i++) {
                uint32_t p = s[i];
                o[i] = lr[p & 255] | lg[(p >> 8) & 255] | lb[(p >> 16) & 255];
            }
        }
    }
    return 0;
}

int mvs_blit_bgra(const mvs_decoder *d, int x, int y, int w, int h, void *dst, size_t stride) {
    if (!d->fb || !dst) return -1;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > d->fbW) w = d->fbW - x;
    if (y + h > d->fbH) h = d->fbH - y;
    if (w <= 0 || h <= 0) return 0;
    for (int row = 0; row < h; row++) {
        const uint32_t *s = d->fb + (size_t)(y + row) * d->fbW + x;
        uint32_t *o = (uint32_t *)((uint8_t *)dst + (size_t)(y + row) * stride + (size_t)x * 4);
        for (int i = 0; i < w; i++) {
            uint32_t p = s[i];
            o[i] = 0xFF000000u | (p & 255) << 16 | (p & 0xFF00) | (p >> 16 & 255);
        }
    }
    return 0;
}

const char *mvs_strerror(int code) {
    switch (code) {
    case MVS_OK: return "ok";
    case MVS_ERR_RECT: return "rect outside the framebuffer";
    case MVS_ERR_TRUNC: return "data ended early";
    case MVS_ERR_DATA: return "invalid data";
    case MVS_ERR_TYPE: return "unknown update type";
    case MVS_ERR_QUANT: return "quantization packet is not 129 bytes";
    case MVS_ERR_SIZE: return "too large";
    case MVS_ERR_NOMEM: return "out of memory";
    }
    return "unknown error";
}
