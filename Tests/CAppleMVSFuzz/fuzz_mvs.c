/*
 * Fuzz target for the 1011 (MVS) decoder in Sources/CAppleMVS: one input is a
 * sequence of operations on one decoder, so full updates, the partial updates
 * coded against them, the tile cache, resets and size changes are reached in
 * the same run. Uses only the public API (mvs.h).
 *
 * Built two ways (see the Makefile):
 *  - with libFuzzer (`make fuzz`, needs a clang that ships libFuzzer): coverage
 *    guided, LLVMFuzzerTestOneInput is called by libFuzzer's main;
 *  - as a replay tool (`make replay`, any C compiler, AddressSanitizer +
 *    UBSan): -DMVS_FUZZ_REPLAY adds a main that runs every file named on the
 *    command line, or every file in a named directory, once.
 *
 * Input:
 *   byte 0, 1   framebuffer width and height, each % 65 (0..64)
 *   then records until the input ends:
 *   op a b c e  five bytes; op % 4 selects:
 *     0  decode a rect: x = a % (fbw + 1), y = b % (fbh + 1),
 *        w = c % (fbw - x + 2), h = e % (fbh - y + 2) (so the rect may end
 *        one pixel past the framebuffer), followed by
 *        lenHi lenLo and that many body bytes (fewer if the input ends)
 *     1  decode a 0x0 rect at 0,0 (how quantization tables arrive), same
 *        length and body as op 0; a, b, c, e unused
 *     2  mvs_reset
 *     3  new framebuffer size a % 65 by b % 65 for the following rects
 *   For ops 0 and 1 the other bits of op shape the blit destination: rows of
 *   (op >> 5 & 1 ? the region's right edge : fbw) + (op >> 2 & 7) pixels.
 *
 * Frames stay at most 64x64 (8x8 tiles) to keep runs fast: the decoder's
 * index arithmetic does not depend on the frame size beyond what the unit
 * tests cover (the size limits, negative and odd sizes).
 *
 * Each body is copied into an allocation of exactly its length, so a read
 * past the end is caught. After each decode the target checks what callers
 * rely on and aborts if it does not hold: a known return code, the changed
 * region inside the rect and the framebuffer, or 0,0 0x0 when nothing
 * changed, and the decoder's picture the size of the framebuffer. It then
 * blits the changed region with mvs_blit_bgra and mvs_blit (16 and 32 bpp)
 * into a buffer that ends at the region's last byte, the smallest one the
 * documented precondition allows, with rows that may be narrower than the
 * decoder's picture or padded.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "mvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIDE 64

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "fuzz_mvs: invariant failed: %s\n", what);
        abort();
    }
}

static int known_code(int rc) {
    return rc == MVS_OK || rc == MVS_ERR_RECT || rc == MVS_ERR_TRUNC || rc == MVS_ERR_DATA ||
           rc == MVS_ERR_TYPE || rc == MVS_ERR_QUANT || rc == MVS_ERR_SIZE || rc == MVS_ERR_NOMEM;
}

/* Blits the region into a buffer of rowPx-pixel rows that ends exactly at the
 * region's last pixel. */
static void blit_region(const mvs_decoder *d, int rowPx, const mvs_result *r) {
    for (int mode = 0; mode < 3; mode++) {
        size_t bpp = mode == 1 ? 2 : 4;
        size_t stride = (size_t)rowPx * bpp;
        size_t size = (size_t)(r->y + r->h - 1) * stride + (size_t)(r->x + r->w) * bpp;
        uint8_t *dst = malloc(size);
        check(dst != NULL, "blit buffer allocated");
        int rc;
        if (mode == 0) rc = mvs_blit_bgra(d, r->x, r->y, r->w, r->h, dst, stride);
        else if (mode == 1) rc = mvs_blit(d, r->x, r->y, r->w, r->h, dst, stride, 16, 10, 5, 0, 31, 31, 31);
        else rc = mvs_blit(d, r->x, r->y, r->w, r->h, dst, stride, 32, 16, 8, 0, 255, 255, 255);
        check(rc == 0, "blit of a decoded region succeeds");
        free(dst);
    }
}

static void decode(mvs_decoder *d, int fbw, int fbh, int x, int y, int w, int h,
                   const uint8_t *data, size_t len, int dstShape) {
    uint8_t *body = malloc(len ? len : 1);
    check(body != NULL, "body allocated");
    if (len) memcpy(body, data, len);
    mvs_result r;
    int rc = mvs_decode_rect(d, fbw, fbh, x, y, w, h, len ? body : NULL, len, &r);
    free(body);

    check(known_code(rc), "known return code");
    check(r.warnings >= 0, "warnings not negative");
    if (rc == MVS_ERR_SIZE || rc == MVS_ERR_NOMEM) return;
    int pw = -1, ph = -1;
    const uint32_t *px = mvs_pixels(d, &pw, &ph);
    /* a 0x0 framebuffer right after mvs_new or mvs_reset has no picture */
    check((px != NULL || (fbw == 0 && fbh == 0)) && pw == fbw && ph == fbh, "picture has the framebuffer's size");
    if (r.w <= 0 || r.h <= 0) {
        check(r.x == 0 && r.y == 0 && r.w == 0 && r.h == 0, "nothing changed is 0,0 0x0");
        return;
    }
    check(r.x >= x && r.y >= y && r.x + r.w <= x + w && r.y + r.h <= y + h, "changed region inside the rect");
    check(r.x + r.w <= fbw && r.y + r.h <= fbh, "changed region inside the framebuffer");
    int rowPx = ((dstShape >> 3) & 1 ? r.x + r.w : fbw) + (dstShape & 7);
    blit_region(d, rowPx, &r);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    int fbw = data[0] % (MAX_SIDE + 1), fbh = data[1] % (MAX_SIDE + 1);
    size_t pos = 2;
    mvs_decoder *d = mvs_new();
    check(d != NULL, "decoder allocated");

    while (size - pos >= 5) {
        int op = data[pos] & 3, dstShape = data[pos] >> 2, a = data[pos + 1], b = data[pos + 2], c = data[pos + 3], e = data[pos + 4];
        pos += 5;
        if (op == 2) { mvs_reset(d); continue; }
        if (op == 3) { fbw = a % (MAX_SIDE + 1); fbh = b % (MAX_SIDE + 1); continue; }
        if (size - pos < 2) break;
        size_t len = ((size_t)data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (len > size - pos) len = size - pos;
        int x = 0, y = 0, w = 0, h = 0;
        if (op == 0) {
            x = a % (fbw + 1);
            y = b % (fbh + 1);
            w = c % (fbw - x + 2);
            h = e % (fbh - y + 2);
        }
        decode(d, fbw, fbh, x, y, w, h, data + pos, len, dstShape);
        pos += len;
    }
    mvs_free(d);
    return 0;
}

#ifdef MVS_FUZZ_REPLAY
#include <dirent.h>
#include <sys/stat.h>

static int run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    uint8_t *buf = NULL;
    size_t n = 0, cap = 0;
    for (;;) {
        if (n == cap) {
            cap = cap ? cap * 2 : 4096;
            uint8_t *grown = realloc(buf, cap);
            if (!grown) { free(buf); fclose(f); fprintf(stderr, "%s: out of memory\n", path); return 1; }
            buf = grown;
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) break;
    }
    int bad = ferror(f);
    fclose(f);
    if (bad) { free(buf); fprintf(stderr, "%s: read error\n", path); return 1; }
    /* exact-size copy so ASan sees a read past the input */
    uint8_t *exact = malloc(n ? n : 1);
    if (!exact) { free(buf); fprintf(stderr, "%s: out of memory\n", path); return 1; }
    if (n) memcpy(exact, buf, n);
    free(buf);
    LLVMFuzzerTestOneInput(exact, n);
    free(exact);
    return 0;
}

int main(int argc, char **argv) {
    int files = 0, errors = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s file-or-directory...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st) != 0) { perror(argv[i]); errors++; continue; }
        if (!S_ISDIR(st.st_mode)) { errors += run_file(argv[i]); files++; continue; }
        DIR *dir = opendir(argv[i]);
        if (!dir) { perror(argv[i]); errors++; continue; }
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char path[4096];
            if (snprintf(path, sizeof path, "%s/%s", argv[i], ent->d_name) >= (int)sizeof path) { errors++; continue; }
            if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            errors += run_file(path);
            files++;
        }
        closedir(dir);
    }
    printf("fuzz_mvs: %d inputs replayed, %d unreadable\n", files, errors);
    return errors ? 1 : 0;
}
#endif
