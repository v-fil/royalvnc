/*
 * Unit tests for the 1011 (MVS) decoder in Sources/CAppleMVS: hand-built
 * bitstream cases ported from noVNC-ARD's test.mvs.js, malformed-input cases,
 * random damage, and the blit helpers. Build and run with `make test` in this
 * directory (AddressSanitizer + UBSan).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Ported from noVNC-ARD (MPL 2.0), https://github.com/peetinc/noVNC-ARD
 */
#include "../../Sources/CAppleMVS/mvs.c" /* included, not linked, so the tests can reach internals */

#include <stdio.h>

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
    rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(rng_state >> 33);
}

static int tests_run = 0, tests_failed = 0;
#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) { printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); tests_failed++; } \
    } while (0)
#define TEST(name) \
    do { tests_run++; printf("test %s\n", name); } while (0)

/* A growing buffer of bits; spaces in strings are ignored. */
typedef struct { uint8_t b[512]; int nbits; } bitbuf;

static void put_bits(bitbuf *o, const char *s) {
    for (; *s; s++) {
        if (*s == ' ') continue;
        if (*s == '1') o->b[o->nbits >> 3] |= 0x80 >> (o->nbits & 7);
        o->nbits++;
    }
}
static void put_marker(bitbuf *o, const char *text) {
    for (; *text; text++)
        for (int i = 7; i >= 0; i--) {
            if ((*text >> i) & 1) o->b[o->nbits >> 3] |= 0x80 >> (o->nbits & 7);
            o->nbits++;
        }
}
static int nbytes(const bitbuf *o) { return (o->nbits + 7) / 8; }

typedef struct { uint8_t b[1024]; size_t n; } packet;

static packet full_update(int t1, int t2, const bitbuf *header, const bitbuf *body) {
    packet p;
    int hn = nbytes(header), off = 6 + hn;
    uint8_t head[6] = {0x00, (uint8_t)t1, (uint8_t)t2, (uint8_t)(off >> 16), (uint8_t)(off >> 8), (uint8_t)off};
    memcpy(p.b, head, 6);
    memcpy(p.b + 6, header->b, hn);
    memcpy(p.b + off, body->b, nbytes(body));
    p.n = off + nbytes(body);
    return p;
}

static packet partial_update(int crLimit, int cbLimit, const bitbuf *body) {
    packet p;
    p.b[0] = 1; p.b[1] = (uint8_t)crLimit; p.b[2] = (uint8_t)cbLimit;
    memcpy(p.b + 3, body->b, nbytes(body));
    p.n = 3 + nbytes(body);
    return p;
}

#define EOB "1010" /* K.5 code for symbol 0x00 */
#define W 16
#define H 8

static packet P_FULL, P_FULL_AC, P_PARTIAL_CR_UP, P_PARTIAL_UNCHANGED, P_CACHE_1, P_CACHE_NEXT, P_PARTIAL_AC1, P_PARTIAL_AC0;

static void build_packets(void) {
    bitbuf h, b;
    /* Full update: tile 0 is a DCT tile with Y DC = 10 and neutral chroma, tile 1 repeats it. */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0 101 1 0000"); put_marker(&h, "m");
    put_bits(&b, "0 0 0 00 00 1110 010 1 0 01 0 1"); put_marker(&b, "m");
    P_FULL = full_update(15, 25, &h, &b);
    /* Same, with Y AC position 1 = +2 */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0 101 1 0000"); put_marker(&h, "m");
    put_bits(&b, "0 0 0 00 00 1110 010 1 0 10 0 01 0 1"); put_marker(&b, "m");
    P_FULL_AC = full_update(15, 25, &h, &b);

    for (int step = 0; step < 2; step++) {
        memset(&b, 0, sizeof b);
        put_bits(&b, "01 000001");
        put_bits(&b, step ? "1" : "0");
        put_bits(&b, "0 " EOB " 0 " EOB " 00");
        put_marker(&b, "mvs");
        if (step) P_PARTIAL_AC1 = partial_update(14, 19, &b); else P_PARTIAL_AC0 = partial_update(14, 19, &b);
    }
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 000000 1 0 " EOB " 0 " EOB " 00"); put_marker(&b, "mvs");
    P_PARTIAL_CR_UP = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 000000 0 " EOB " 0 " EOB " 00"); put_marker(&b, "mvs");
    P_PARTIAL_UNCHANGED = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "00 11 0 0000000000000001"); put_marker(&b, "mvs");
    P_CACHE_1 = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "00 11 1"); put_marker(&b, "mvs");
    P_CACHE_NEXT = partial_update(14, 19, &b);
}

typedef struct { mvs_decoder *d; int fbw, fbh, warnings, rc; } sess;

static sess sess_new(int fbw, int fbh) { return (sess){mvs_new(), fbw, fbh, 0, 0}; }
static void dec(sess *s, const packet *p, int x, int y) {
    mvs_result r;
    s->rc = mvs_decode_rect(s->d, s->fbw, s->fbh, x, y, W, H, p->b, p->n, &r);
    s->warnings = r.warnings;
}
static uint32_t pix(sess *s, int x, int y) { return s->d->fb[(size_t)y * s->d->fbW + x]; }
static uint32_t RGB(int r, int g, int b) { return rgba(r, g, b); }

static void tile_pixels(sess *s, int tile, uint32_t *out) {
    for (int row = 0; row < 8; row++)
        for (int col = 0; col < 8; col++) out[row * 8 + col] = pix(s, tile * 8 + col, row);
}

static void run_seq(sess *s, const packet **ps, int n) {
    for (int i = 0; i < n; i++) dec(s, ps[i], 0, 0);
}

static void test_ported(void) {
    const uint32_t GRAY = RGB(148, 148, 148), REDDISH = RGB(151, 147, 148);
    sess s;

    TEST("full update: a DCT tile and a repeat of it");
    s = sess_new(W, H);
    dec(&s, &P_FULL, 0, 0);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 0, 0) == GRAY && pix(&s, 8, 0) == GRAY);
    mvs_free(s.d);

    TEST("full update: dequantizes with tables from a quantization update");
    s = sess_new(W, H);
    uint8_t tables[129];
    memset(tables, 8, 129);
    tables[0] = 2;
    mvs_result r;
    CHECK(mvs_decode_rect(s.d, W, H, 0, 0, 0, 0, tables, 129, &r) == MVS_OK);
    dec(&s, &P_FULL, 0, 0);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 0, 0) == RGB(138, 138, 138));
    mvs_free(s.d);

    TEST("partial update: applies a chroma DC step to a DCT tile");
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL, &P_PARTIAL_CR_UP}, 2);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 0, 0) == REDDISH && pix(&s, 8, 0) == GRAY);
    mvs_free(s.d);

    TEST("partial update: codes every partial against the last full update");
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL, &P_PARTIAL_CR_UP, &P_PARTIAL_UNCHANGED}, 3);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 0, 0) == GRAY);
    mvs_free(s.d);

    TEST("partial update: Y AC baseline comes from the full update too");
    uint32_t full[64], stepped[64], back[64];
    s = sess_new(W, H);
    dec(&s, &P_FULL_AC, 0, 0);
    tile_pixels(&s, 0, full);
    mvs_free(s.d);
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL_AC, &P_PARTIAL_AC1}, 2);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    tile_pixels(&s, 0, stepped);
    CHECK(memcmp(full, stepped, sizeof full) != 0);
    mvs_free(s.d);
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL_AC, &P_PARTIAL_AC1, &P_PARTIAL_AC0}, 3);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    tile_pixels(&s, 0, back);
    CHECK(memcmp(full, back, sizeof full) == 0);
    mvs_free(s.d);

    TEST("partial update: caches partial DCT tiles only, starting at slot 1");
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL, &P_PARTIAL_CR_UP, &P_PARTIAL_UNCHANGED, &P_CACHE_1}, 4);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 8, 0) == REDDISH);
    mvs_free(s.d);

    TEST("partial update: 'next' is the slot after the last one loaded");
    s = sess_new(W, H);
    run_seq(&s, (const packet *[]){&P_FULL, &P_PARTIAL_CR_UP, &P_PARTIAL_UNCHANGED, &P_CACHE_1, &P_CACHE_NEXT}, 5);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 8, 0) == GRAY);
    mvs_free(s.d);

    TEST("partial update: rejects a cache slot that was never written");
    s = sess_new(W, H);
    dec(&s, &P_FULL, 0, 0);
    dec(&s, &P_CACHE_1, 0, 0);
    CHECK(s.warnings == 1);
    CHECK(pix(&s, 8, 0) == GRAY);
    mvs_free(s.d);

    /* A 16x8 display placed at 16,3 in a 32x16 framebuffer */
    TEST("rect inside a larger framebuffer: not on a tile boundary");
    s = sess_new(32, 16);
    dec(&s, &P_FULL, 16, 3);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 16, 3) == GRAY && pix(&s, 31, 10) == GRAY);
    CHECK(pix(&s, 16, 2) == 0 && pix(&s, 16, 11) == 0 && pix(&s, 15, 3) == 0);
    mvs_free(s.d);

    TEST("rect inside a larger framebuffer: baseline and cache are kept");
    s = sess_new(32, 16);
    for (int i = 0; i < 4; i++) dec(&s, (const packet *[]){&P_FULL, &P_PARTIAL_CR_UP, &P_PARTIAL_UNCHANGED, &P_CACHE_1}[i], 16, 3);
    CHECK(s.rc == MVS_OK && s.warnings == 0);
    CHECK(pix(&s, 16, 3) == GRAY && pix(&s, 24, 3) == REDDISH);
    mvs_free(s.d);

    TEST("rect inside a larger framebuffer: rejects one that leaves it");
    s = sess_new(32, 16);
    dec(&s, &P_FULL, 24, 3);
    CHECK(s.rc == MVS_ERR_RECT && s.warnings == 1);
    CHECK(pix(&s, 24, 3) == 0);
    mvs_free(s.d);

    TEST("inverse DCT: a DC-only block equals the flat shortcut for every DC");
    int32_t block[64] = {0};
    uint8_t samples[64];
    int bad = 0;
    for (int dc = -40000; dc <= 40000; dc++) {
        block[0] = dc;
        idct8x8(block, samples);
        int flat = idct_flat(dc);
        if (samples[0] != flat || samples[63] != flat) bad++;
    }
    CHECK(bad == 0);
}

/* Extra cases for the C port: network input must never crash. */
static void test_malformed(void) {
    sess s;
    mvs_result r;
    uint8_t junk[40];

    TEST("malformed: every truncation of the full and partial packets");
    const packet *all[] = {&P_FULL, &P_FULL_AC, &P_PARTIAL_CR_UP, &P_PARTIAL_AC1, &P_CACHE_1, &P_CACHE_NEXT};
    int clean = 0, errors = 0;
    for (size_t k = 0; k < sizeof all / sizeof *all; k++)
        for (size_t len = 0; len <= all[k]->n; len++) {
            s = sess_new(W, H);
            dec(&s, &P_FULL, 0, 0);
            dec(&s, &P_PARTIAL_CR_UP, 0, 0);
            packet p = *all[k];
            p.n = len;
            /* exact-size copy so ASan sees any read past the end */
            uint8_t *copy = malloc(len ? len : 1);
            memcpy(copy, p.b, len);
            int rc = mvs_decode_rect(s.d, W, H, 0, 0, W, H, copy, len, &r);
            if (rc == MVS_OK) clean++; else errors++;
            free(copy);
            mvs_free(s.d);
        }
    CHECK(errors > 0 && clean > 0);

    TEST("malformed: empty body, unknown type, wrong-size tables, huge body");
    s = sess_new(W, H);
    CHECK(mvs_decode_rect(s.d, W, H, 0, 0, W, H, junk, 0, &r) == MVS_ERR_TYPE);
    junk[0] = 9;
    CHECK(mvs_decode_rect(s.d, W, H, 0, 0, W, H, junk, 40, &r) == MVS_ERR_TYPE);
    junk[0] = 2;
    CHECK(mvs_decode_rect(s.d, W, H, 0, 0, 0, 0, junk, 40, &r) == MVS_ERR_QUANT);
    CHECK(mvs_decode_rect(s.d, W, H, 0, 0, W, H, junk, (size_t)MVS_MAX_BODY + 1, &r) == MVS_ERR_SIZE);
    mvs_free(s.d);

    TEST("malformed: bad body offset in a full update");
    s = sess_new(W, H);
    packet p = P_FULL;
    p.b[3] = 0xff; /* offset far past the end */
    dec(&s, &p, 0, 0);
    CHECK(s.rc == MVS_ERR_DATA);
    p = P_FULL;
    p.b[3] = 0; p.b[4] = 0; p.b[5] = 5; /* offset < 6 */
    dec(&s, &p, 0, 0);
    CHECK(s.rc == MVS_ERR_DATA);
    mvs_free(s.d);

    TEST("malformed: framebuffer too large, negative or odd sizes");
    mvs_decoder *d = mvs_new();
    CHECK(mvs_decode_rect(d, 65535, 65535, 0, 0, 0, 0, P_FULL.b, P_FULL.n, &r) == MVS_ERR_SIZE);
    CHECK(mvs_decode_rect(d, -1, 8, 0, 0, 0, 0, P_FULL.b, P_FULL.n, &r) == MVS_ERR_RECT);
    CHECK(mvs_decode_rect(d, 16, 8, 0, 0, 65535, 65535, P_FULL.b, P_FULL.n, &r) == MVS_ERR_RECT);
    CHECK(mvs_decode_rect(d, 16, 8, 65535, 65535, 65535, 65535, P_FULL.b, P_FULL.n, &r) == MVS_ERR_RECT);
    CHECK(mvs_decode_rect(d, 0, 0, 0, 0, 0, 0, P_FULL.b, P_FULL.n, &r) != MVS_ERR_SIZE); /* 0x0 screen */
    mvs_free(d);

    TEST("malformed: partial update with no baseline, and with no framebuffer");
    s = sess_new(W, H);
    dec(&s, &P_PARTIAL_CR_UP, 0, 0);
    CHECK(s.rc == MVS_ERR_DATA);
    mvs_free(s.d);
    d = mvs_new();
    CHECK(mvs_decode_rect(d, 0, 0, 0, 0, 0, 0, P_PARTIAL_CR_UP.b, P_PARTIAL_CR_UP.n, &r) != MVS_ERR_SIZE);
    mvs_free(d);

    TEST("malformed: repeat tile with no previous DCT tile warns");
    {
        bitbuf h, b;
        memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
        put_bits(&h, "0 101 0"); put_marker(&h, "m"); /* one DCT tile */
        put_bits(&b, "1"); put_marker(&b, "m");      /* repeat bit set */
        packet q = full_update(15, 25, &h, &b);
        s = sess_new(8, 8);
        mvs_result rr;
        s.rc = mvs_decode_rect(s.d, 8, 8, 0, 0, 8, 8, q.b, q.n, &rr);
        CHECK(rr.warnings == 1);
        mvs_free(s.d);
    }

    TEST("malformed: tile copies at the edges (match above on row 0, match previous on tile 0)");
    {
        bitbuf h, b;
        memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
        /* tile 0 type 2 (above: nothing there), tile 1 type 1 (previous), run of 1 each */
        put_bits(&h, "0 010 0 001 0"); put_marker(&h, "m");
        put_marker(&b, "m");
        packet q = full_update(15, 25, &h, &b);
        s = sess_new(W, H);
        mvs_result rr;
        s.rc = mvs_decode_rect(s.d, W, H, 0, 0, W, H, q.b, q.n, &rr);
        CHECK(s.rc == MVS_OK && rr.warnings == 0);
        mvs_free(s.d);
    }

    TEST("malformed: cache slot 65000 (one past the JS array) reads as zeros, 65001 is rejected");
    {
        s = sess_new(W, H);
        dec(&s, &P_FULL, 0, 0);
        dec(&s, &P_PARTIAL_CR_UP, 0, 0); /* allocates the cache */
        s.d->cacheCount = 1000000;
        CHECK(load_cache_and_render(s.d, 65000) == 1);
        CHECK(load_cache_and_render(s.d, 65001) == 0);
        CHECK(load_cache_and_render(s.d, 0) == 0);
        mvs_free(s.d);
    }

    TEST("malformed: huge Rice prefix wraps like the JS without crashing");
    {
        /* tile 0 DCT, dcMode 0: Cb Rice = 40 ones then 0 ... then more ones */
        bitbuf h, b;
        memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
        put_bits(&h, "0 101 0"); put_marker(&h, "m");
        put_bits(&b, "0 0 0");
        for (int i = 0; i < 100; i++) put_bits(&b, "1");
        put_bits(&b, "0 111 0 000 0 000 0 000");
        packet q = full_update(15, 25, &h, &b);
        s = sess_new(8, 8);
        mvs_result rr;
        s.rc = mvs_decode_rect(s.d, 8, 8, 0, 0, 8, 8, q.b, q.n, &rr);
        CHECK(s.rc == MVS_OK || s.rc == MVS_ERR_TRUNC);
        mvs_free(s.d);
    }

    TEST("malformed: random damage to the hand-built packets (ASan/UBSan)");
    {
        const packet *src[] = {&P_FULL, &P_FULL_AC, &P_PARTIAL_CR_UP, &P_PARTIAL_AC1, &P_CACHE_1, &P_CACHE_NEXT, &P_PARTIAL_UNCHANGED};
        for (int it = 0; it < 20000; it++) {
            s = sess_new(32, 16);
            for (int step = 0; step < 6; step++) {
                const packet *base = src[rnd() % 7];
                size_t len = base->n;
                uint8_t *copy = malloc(len);
                memcpy(copy, base->b, len);
                for (int j = 0, m = (int)(rnd() % 4); j < m; j++) copy[rnd() % len] ^= (uint8_t)(1u << (rnd() % 8));
                if (rnd() % 4 == 0) len = rnd() % (len + 1);
                int x = (int)(rnd() % 20), y = (int)(rnd() % 10);
                mvs_result rr;
                mvs_decode_rect(s.d, 32, 16, x, y, W, H, copy, len, &rr);
                free(copy);
            }
            mvs_free(s.d);
        }
        CHECK(1);
    }

    TEST("blit: 16bpp RGB555 and 32bpp conversion, clipping");
    {
        s = sess_new(W, H);
        dec(&s, &P_FULL, 0, 0);
        uint16_t out16[W * H];
        uint32_t out32[W * H];
        memset(out16, 0, sizeof out16);
        memset(out32, 0, sizeof out32);
        CHECK(mvs_blit(s.d, -5, -5, 100, 100, out16, W * 2, 16, 10, 5, 0, 31, 31, 31) == 0);
        CHECK(out16[0] == (uint16_t)((18 << 10) | (18 << 5) | 18)); /* 148 -> (148*31+127)/255 = 18 */
        CHECK(mvs_blit(s.d, 0, 0, W, H, out32, W * 4, 32, 0, 8, 16, 255, 255, 255) == 0);
        CHECK(out32[0] == 0x00949494u);
        CHECK(mvs_blit(s.d, 0, 0, W, H, out32, W * 4, 8, 0, 0, 0, 7, 7, 3) == -1);
        mvs_free(s.d);
    }

    TEST("blit_bgra: B,G,R,A bytes with alpha 255, clipping");
    {
        s = sess_new(W, H);
        dec(&s, &P_FULL, 0, 0);
        uint8_t bgra[W * H * 4];
        memset(bgra, 0, sizeof bgra);
        CHECK(mvs_blit_bgra(s.d, -5, -5, 100, 100, bgra, W * 4) == 0);
        CHECK(bgra[0] == 148 && bgra[1] == 148 && bgra[2] == 148 && bgra[3] == 255);
        CHECK(bgra[(H - 1) * W * 4 + (W - 1) * 4 + 3] == 255); /* last pixel covered */
        /* a coloured pixel lands in memory as B,G,R,A */
        s.d->fb[0] = RGB(10, 20, 30);
        memset(bgra, 0, sizeof bgra);
        CHECK(mvs_blit_bgra(s.d, 0, 0, 1, 1, bgra, W * 4) == 0);
        CHECK(bgra[0] == 30 && bgra[1] == 20 && bgra[2] == 10 && bgra[3] == 255);
        CHECK(bgra[4] == 0 && bgra[W * 4] == 0); /* nothing outside the 1x1 region */
        CHECK(mvs_blit_bgra(s.d, W, H, 4, 4, bgra, W * 4) == 0); /* fully outside: no-op */
        mvs_free(s.d);
        mvs_decoder *none = mvs_new();
        CHECK(mvs_blit_bgra(none, 0, 0, 1, 1, bgra, W * 4) == -1); /* no framebuffer */
        mvs_free(none);
    }
}
int main(void) {
    build_packets();
    test_ported();
    test_malformed();
    printf("%d tests, %d check failures\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
