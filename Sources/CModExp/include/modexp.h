#ifndef RVNC_MODEXP_H
#define RVNC_MODEXP_H

#include <stddef.h>
#include <stdint.h>

#define RVNC_MODEXP_MAX_BYTES 512

/* out = base^exp mod mod. All numbers are big-endian bytes; out gets mod_len bytes,
 * zero-padded. The modulus must be odd, at most RVNC_MODEXP_MAX_BYTES long and greater
 * than 1; base must be less than it. Montgomery multiplication with 4-bit windows; not
 * constant time. Returns 0, or -1 for invalid input. */
int rvnc_modexp(const uint8_t *base, size_t base_len,
                const uint8_t *exp, size_t exp_len,
                const uint8_t *mod, size_t mod_len,
                uint8_t *out);

#endif
