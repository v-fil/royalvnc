/*
 * Apple VNC encoding 1011 ("MVS") decoder: pure C, no dependencies beyond libc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Port of the noVNC-ARD JavaScript decoder (MPL 2.0),
 *   https://github.com/peetinc/noVNC-ARD  (commit d699293635083c9e0c30c8f9480993865653772a)
 *   ard/decoders/mvs.js, mvs-bitstream.js, mvs-rice.js, mvs-huffman.js,
 *   mvs-idct.js, mvs-tables.js
 * which in turn follows Apple's viewer (DecodeMultiVariant.c). The format is
 * undocumented.
 *
 * Usage: feed each 1011 rect body (the bytes after the 4-byte length) to
 * mvs_decode_rect(). The decoder keeps its own RGBA framebuffer (it needs it
 * for tile copies); mvs_blit() converts a region of it to the client's pixel
 * format. One decoder per connection; not thread-safe.
 */
#ifndef YAVNC_MVS_H
#define YAVNC_MVS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest rect body accepted (the same limit the app uses for other encodings). */
#define MVS_MAX_BODY (64u << 20)
/* Largest framebuffer the decoder will allocate, in pixels (128 MB of RGBA). */
#define MVS_MAX_PIXELS (1u << 25)

/* Return codes of mvs_decode_rect(). Anything but MVS_OK means the update was
 * not fully applied. As in the JavaScript decoder, whatever was decoded before
 * the problem stays in the framebuffer and the decoder remains usable. */
enum {
    MVS_OK = 0,
    MVS_ERR_RECT = -1,   /* rect outside the framebuffer: ignored */
    MVS_ERR_TRUNC = -2,  /* a bit read ran past the end of the data */
    MVS_ERR_DATA = -3,   /* invalid header, Huffman code or missing baseline */
    MVS_ERR_TYPE = -4,   /* unknown update type, or empty body */
    MVS_ERR_QUANT = -5,  /* quantization packet of the wrong size: ignored */
    MVS_ERR_SIZE = -6,   /* body or framebuffer larger than the limits */
    MVS_ERR_NOMEM = -7
};

typedef struct {
    /* Region of the framebuffer that changed; w == 0 means nothing. Set also
     * when the update failed part way, because the tiles done so far are drawn. */
    int x, y, w, h;
    /* Soft problems the JS decoder only logs: end marker mismatch, cache index
     * out of range, repeat tile without a previous one. */
    int warnings;
} mvs_result;

typedef struct mvs_decoder mvs_decoder;

mvs_decoder *mvs_new(void);
void mvs_free(mvs_decoder *d);

/* Forget everything about the picture (framebuffer, tile descriptors, tile
 * cache). Keeps the quantization tables. Call after the server changes its
 * scale: the server restarts its tile state with a full update. */
void mvs_reset(mvs_decoder *d);

/* Decode one rect body. fb_w/fb_h are the framebuffer size; when they change
 * the screen state is reset (like the JS decoder). Rects of type 2
 * (quantization tables) normally arrive as 0x0 at 0,0. */
int mvs_decode_rect(mvs_decoder *d, int fb_w, int fb_h, int x, int y, int w, int h,
                    const uint8_t *body, size_t len, mvs_result *res);

/* The decoder's framebuffer: width*height pixels, bytes R,G,B,A in memory order
 * (little-endian uint32 = 0xAABBGGRR, alpha always 255). NULL before the first
 * sized rect. */
const uint32_t *mvs_pixels(const mvs_decoder *d, int *width, int *height);

/* Convert a region of the decoder's framebuffer into dst, a framebuffer with
 * the given row stride in bytes and a little-endian 16 or 32 bits-per-pixel
 * format described by channel shifts and maxima (as in an RFB pixel format).
 * The region is clipped to the decoder's framebuffer only: dst must cover the
 * region (it may be larger than the decoder's picture, never smaller where
 * the region lands). Returns 0, or -1 for an unsupported bpp or a decoder
 * without a framebuffer. */
int mvs_blit(const mvs_decoder *d, int x, int y, int w, int h, void *dst, size_t stride,
             int bpp, int rshift, int gshift, int bshift, int rmax, int gmax, int bmax);

/* Like mvs_blit() into a 32 bits-per-pixel framebuffer of bytes B,G,R,A in
 * memory order (little-endian uint32 = 0xAARRGGBB), alpha 255. */
int mvs_blit_bgra(const mvs_decoder *d, int x, int y, int w, int h, void *dst, size_t stride);

const char *mvs_strerror(int code);

#ifdef __cplusplus
}
#endif
#endif
