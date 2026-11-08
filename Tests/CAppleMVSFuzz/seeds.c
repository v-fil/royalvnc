/*
 * Writes the seed corpus for fuzz_mvs.c into a directory: synthetic inputs
 * only, built bit by bit like the cases in Tests/CAppleMVSTests (noVNC-ARD's
 * test cases and more). Each seed is a sequence of operations in the
 * fuzz_mvs.c input format. `seeds <directory>`; the Makefile runs it.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- bitstreams */

/* A growing buffer of bits; spaces in strings are ignored. */
typedef struct { uint8_t b[512]; int nbits; } bitbuf;

static void put_bits(bitbuf *o, const char *s) {
    for (; *s; s++) {
        if (*s == ' ') continue;
        if (o->nbits >= (int)sizeof o->b * 8) { fprintf(stderr, "seeds: bit buffer full\n"); exit(1); }
        if (*s == '1') o->b[o->nbits >> 3] |= 0x80 >> (o->nbits & 7);
        o->nbits++;
    }
}
static void put_marker(bitbuf *o, const char *text) {
    char bits[9];
    for (; *text; text++) {
        for (int i = 0; i < 8; i++) bits[i] = ((*text >> (7 - i)) & 1) ? '1' : '0';
        bits[8] = 0;
        put_bits(o, bits);
    }
}
static int nbytes(const bitbuf *o) { return (o->nbits + 7) / 8; }

typedef struct { uint8_t b[1100]; size_t n; } packet;

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

static packet quant_tables(int len, uint8_t value) {
    packet p;
    memset(p.b, value, (size_t)len);
    p.b[0] = 2;
    p.n = (size_t)len;
    return p;
}

#define EOB "1010" /* K.5 code for symbol 0x00 */
/* One full-update DCT tile: Y DC 10, neutral chroma, no AC (repeat bit, dcMode,
 * threshold bit, Cb and Cr Rice 0, Y DC Rice -10, EOB). */
#define DCT_TILE "0 0 0 00 00 1110 010 1 0 01 0"

/* --------------------------------------------------------------- seed file */

typedef struct { uint8_t b[8192]; size_t n; } seed;

static void put(seed *s, const uint8_t *p, size_t n) {
    if (s->n + n > sizeof s->b) { fprintf(stderr, "seeds: seed too large\n"); exit(1); }
    memcpy(s->b + s->n, p, n);
    s->n += n;
}
static seed start(int fbw, int fbh) {
    seed s = {{0}, 0};
    uint8_t head[2] = {(uint8_t)fbw, (uint8_t)fbh};
    put(&s, head, 2);
    return s;
}
/* op 0: a rect (x, y, w, h as the fuzz target reads them for this framebuffer) */
static void rect(seed *s, int x, int y, int w, int h, const packet *p) {
    uint8_t rec[7] = {0, (uint8_t)x, (uint8_t)y, (uint8_t)w, (uint8_t)h, (uint8_t)(p->n >> 8), (uint8_t)p->n};
    put(s, rec, 7);
    put(s, p->b, p->n);
}
/* op 1: a 0x0 rect at 0,0 */
static void rect0(seed *s, const packet *p) {
    uint8_t rec[7] = {1, 0, 0, 0, 0, (uint8_t)(p->n >> 8), (uint8_t)p->n};
    put(s, rec, 7);
    put(s, p->b, p->n);
}
static void reset(seed *s) { uint8_t rec[5] = {2, 0, 0, 0, 0}; put(s, rec, 5); }
static void resize(seed *s, int w, int h) { uint8_t rec[5] = {3, (uint8_t)w, (uint8_t)h, 0, 0}; put(s, rec, 5); }

static const char *outdir;
static int written = 0;

static void save(const char *name, const seed *s) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", outdir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(s->b, 1, s->n, f) != s->n || fclose(f) != 0) { perror(path); exit(1); }
    written++;
}

/* ------------------------------------------------------------------ seeds */

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s directory\n", argv[0]); return 2; }
    outdir = argv[1];
    bitbuf h, b;
    seed s;

    /* Full update on 16x8: a DCT tile and a repeat of it. */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0 101 1 0000"); put_marker(&h, "m");
    put_bits(&b, DCT_TILE " 1"); put_marker(&b, "m");
    packet full = full_update(15, 25, &h, &b);
    packet full_thr5 = full_update(5, 40, &h, &b);

    /* Same, with Y AC position 1 = +2 */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0 101 1 0000"); put_marker(&h, "m");
    put_bits(&b, "0 0 0 00 00 1110 010 1 0 10 0 01 0 1"); put_marker(&b, "m");
    packet full_ac = full_update(15, 25, &h, &b);

    /* Partial updates against the full update */
    packet partial_ac[2];
    for (int step = 0; step < 2; step++) {
        memset(&b, 0, sizeof b);
        put_bits(&b, "01 000001");
        put_bits(&b, step ? "1" : "0");
        put_bits(&b, "0 " EOB " 0 " EOB " 00");
        put_marker(&b, "mvs");
        partial_ac[step] = partial_update(14, 19, &b);
    }
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 000000 1 0 " EOB " 0 " EOB " 00"); put_marker(&b, "mvs");
    packet cr_up = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 000000 0 " EOB " 0 " EOB " 00"); put_marker(&b, "mvs");
    packet unchanged = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "00 11 0 0000000000000001"); put_marker(&b, "mvs");
    packet cache_1 = partial_update(14, 19, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "00 11 1"); put_marker(&b, "mvs");
    packet cache_next = partial_update(14, 19, &b);
    /* AC count 3 with Rice values, a chroma AC coefficient (symbol 0x01), then a tile copy */
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 000011 1 10 0 0 00 1 " EOB " 1 1 " EOB " 10"); put_marker(&b, "mvs");
    packet partial_rice = partial_update(63, 63, &b);
    /* Threshold below 15: three-bit Y AC deltas */
    memset(&b, 0, sizeof b);
    put_bits(&b, "01 001000 010 011 00 00 00 00 1010 110001 1 0 " EOB " 0 " EOB " 00"); put_marker(&b, "mvs");
    packet partial_thr5 = partial_update(5, 5, &b);

    packet tables = quant_tables(129, 8);
    packet tables_bad = quant_tables(40, 8);

    s = start(16, 8);
    rect(&s, 0, 0, 16, 8, &full);
    save("full-dct-repeat", &s);

    s = start(16, 8);
    rect0(&s, &tables);
    rect(&s, 0, 0, 16, 8, &full);
    rect0(&s, &tables_bad);
    rect(&s, 0, 0, 16, 8, &full_ac);
    save("quant-tables", &s);

    s = start(16, 8);
    rect(&s, 0, 0, 16, 8, &full);
    rect(&s, 0, 0, 16, 8, &cr_up);
    rect(&s, 0, 0, 16, 8, &unchanged);
    rect(&s, 0, 0, 16, 8, &cache_1);
    rect(&s, 0, 0, 16, 8, &cache_next);
    save("partial-cache", &s);

    s = start(16, 8);
    rect(&s, 0, 0, 16, 8, &full_ac);
    rect(&s, 0, 0, 16, 8, &partial_ac[1]);
    rect(&s, 0, 0, 16, 8, &partial_ac[0]);
    rect(&s, 0, 0, 16, 8, &partial_rice);
    save("partial-ac", &s);

    s = start(16, 8);
    rect(&s, 0, 0, 16, 8, &full_thr5);
    rect(&s, 0, 0, 16, 8, &partial_thr5);
    rect0(&s, &tables);
    rect(&s, 0, 0, 16, 8, &cache_1);
    save("threshold-low", &s);

    /* Not on a tile boundary inside a larger framebuffer, and one that leaves it */
    s = start(40, 24);
    rect(&s, 5, 3, 16, 8, &full);
    rect(&s, 5, 3, 16, 8, &cr_up);
    rect(&s, 5, 3, 16, 8, &cache_1);
    rect(&s, 30, 3, 11, 8, &full);
    save("offset-rect", &s);

    /* Reset, size changes and a 0x0 framebuffer between updates */
    s = start(16, 8);
    rect(&s, 0, 0, 16, 8, &full);
    rect(&s, 0, 0, 16, 8, &cr_up);
    reset(&s);
    rect(&s, 0, 0, 16, 8, &cache_1);
    resize(&s, 24, 16);
    rect(&s, 0, 0, 16, 8, &full);
    rect(&s, 8, 8, 16, 8, &full);
    rect(&s, 8, 8, 16, 8, &cr_up);
    resize(&s, 0, 0);
    rect(&s, 0, 0, 0, 0, &full);
    resize(&s, 16, 8);
    rect(&s, 0, 0, 16, 8, &full);
    save("reset-resize", &s);

    /* Full update on 64x64 with every tile type and both run-length forms */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0");
    put_bits(&h, "000 0");          /* tile 0: white */
    put_bits(&h, "001 0");          /* tile 1: copy of the previous tile */
    put_bits(&h, "100 1 0000");     /* tiles 2-3: solid or two-colour, run of 2 */
    put_bits(&b, "0 0 10000000 100000 010000"); /* solid, new colour */
    put_bits(&b, "0 1");                         /* solid, same colour */
    put_bits(&h, "011 0");          /* tile 4: black and white */
    put_bits(&b, "10101010 11110000 00001111 11001100 00110011");
    put_bits(&h, "100 0");          /* tile 5: two colours */
    put_bits(&b, "1 0 11000000 000100 111000 00110000 111100 000011 11100111 00011000 01000010");
    put_bits(&h, "101 1 0000");     /* tiles 6-7: DCT and a repeat */
    put_bits(&b, DCT_TILE " 1");
    put_bits(&h, "110 0");          /* tile 8: cache slot 1 (empty: warns) */
    put_bits(&b, "0000000000000001");
    put_bits(&h, "111 0");          /* tile 9: next cache slot */
    put_bits(&h, "010 0");          /* tile 10: copy of the tile above */
    put_bits(&h, "000 1 1111 00100100"); /* tiles 11-63: white, varint run of 53 */
    put_marker(&h, "m"); put_marker(&b, "m");
    packet all_types = full_update(15, 25, &h, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "00 10 00 00 00 00");                    /* tile 1: copy again */
    put_bits(&b, "01 000000 1 1 " EOB " 0 " EOB);        /* tile 6: DCT, Cr DC -1 */
    put_bits(&b, "00 00 11 1 10 11 0 0000000000000001"); /* tiles 7-11: next slot, copy, slot 1 */
    for (int i = 12; i < 64; i++) put_bits(&b, i % 3 ? "00" : "10");
    put_marker(&b, "mvs");
    packet all_partial = partial_update(14, 19, &b);
    s = start(64, 64);
    rect(&s, 0, 0, 64, 64, &all_types);
    rect(&s, 0, 0, 64, 64, &all_partial);
    rect(&s, 0, 0, 64, 64, &all_types);
    save("all-tile-types", &s);

    /* A long AC skip run and a Rice prefix of 100 ones */
    memset(&h, 0, sizeof h); memset(&b, 0, sizeof b);
    put_bits(&h, "0 101 0"); put_marker(&h, "m");
    put_bits(&b, "0 0 0 00 00 1110 010 1 0 01 1 11 111 111 010 1 10 00 1 0 01 0"); put_marker(&b, "m");
    packet skip = full_update(15, 25, &h, &b);
    memset(&b, 0, sizeof b);
    put_bits(&b, "0 0 0");
    for (int i = 0; i < 100; i++) put_bits(&b, "1");
    put_bits(&b, "0 111 0 000 0 000 0 000");
    packet rice = full_update(15, 25, &h, &b);
    s = start(8, 8);
    rect(&s, 0, 0, 8, 8, &skip);
    rect(&s, 0, 0, 8, 8, &rice);
    save("ac-skip-rice", &s);

    printf("seeds: %d written to %s\n", written, outdir);
    return 0;
}
