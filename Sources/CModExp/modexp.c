/* Modular exponentiation for the Diffie-Hellman logins (Apple Remote Desktop, UltraVNC).
 * Built with optimisation even in debug builds (Package.swift): a 2048-bit exponentiation
 * must not hold up a login. */
#include "modexp.h"

#include <string.h>

#define MAX_LIMBS (RVNC_MODEXP_MAX_BYTES / 4)

/* Big-endian bytes to little-endian 32-bit limbs; false if the value needs more than n limbs. */
static int load(uint32_t *dst, size_t n, const uint8_t *src, size_t len) {
    memset(dst, 0, n * sizeof *dst);
    for (size_t i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8; /* position of src[i]'s lowest bit */
        if (src[i] == 0) continue;
        if (bit / 32 >= n) return 0;
        dst[bit / 32] |= (uint32_t)src[i] << (bit % 32);
    }
    return 1;
}

/* a >= b, both n limbs. */
static int geq(const uint32_t *a, const uint32_t *b, size_t n) {
    for (size_t i = n; i-- > 0;) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return 1;
}

/* a -= b, n limbs; returns the borrow. */
static uint32_t sub(uint32_t *a, const uint32_t *b, size_t n) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        a[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
    return (uint32_t)borrow;
}

/* r = a * b * 2^(-32n) mod m (CIOS). a, b < m; r may alias a or b. */
static void montmul(uint32_t *r, const uint32_t *a, const uint32_t *b,
                    const uint32_t *m, size_t n, uint32_t m0inv) {
    uint32_t t[MAX_LIMBS + 2];
    memset(t, 0, (n + 2) * sizeof *t);
    for (size_t i = 0; i < n; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + carry;
            t[j] = (uint32_t)s;
            carry = s >> 32;
        }
        uint64_t s = (uint64_t)t[n] + carry;
        t[n] = (uint32_t)s;
        t[n + 1] = (uint32_t)(s >> 32);

        uint32_t q = t[0] * m0inv;
        s = (uint64_t)t[0] + (uint64_t)q * m[0];
        carry = s >> 32;
        for (size_t j = 1; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)q * m[j] + carry;
            t[j - 1] = (uint32_t)s;
            carry = s >> 32;
        }
        s = (uint64_t)t[n] + carry;
        t[n - 1] = (uint32_t)s;
        t[n] = t[n + 1] + (uint32_t)(s >> 32);
    }
    if (t[n] != 0 || geq(t, m, n)) sub(t, m, n);
    memcpy(r, t, n * sizeof *r);
}

int rvnc_modexp(const uint8_t *base, size_t base_len,
                const uint8_t *exp, size_t exp_len,
                const uint8_t *mod, size_t mod_len,
                uint8_t *out) {
    if (!base || !exp || !mod || !out || mod_len == 0 || mod_len > RVNC_MODEXP_MAX_BYTES) return -1;

    size_t n = (mod_len + 3) / 4;
    uint32_t m[MAX_LIMBS], b[MAX_LIMBS], r2[MAX_LIMBS], x[MAX_LIMBS], one[MAX_LIMBS];
    uint32_t table[16][MAX_LIMBS];

    if (!load(m, n, mod, mod_len) || !(m[0] & 1)) return -1;
    {
        int big = 0; /* modulus > 1 */
        for (size_t i = 1; i < n; i++) big |= m[i] != 0;
        if (!big && m[0] <= 1) return -1;
    }
    if (!load(b, n, base, base_len) || geq(b, m, n)) return -1;

    /* -m^-1 mod 2^32 by Newton's iteration. */
    uint32_t inv = 1;
    for (int i = 0; i < 5; i++) inv *= 2 - m[0] * inv;
    uint32_t m0inv = (uint32_t)0 - inv;

    /* R^2 mod m, R = 2^(32n): start at 1 and double 64n times. */
    memset(r2, 0, n * sizeof *r2);
    r2[0] = 1;
    for (size_t i = 0; i < 64 * n; i++) {
        uint32_t top = r2[n - 1] >> 31;
        for (size_t j = n; j-- > 1;) r2[j] = r2[j] << 1 | r2[j - 1] >> 31;
        r2[0] <<= 1;
        if (top || geq(r2, m, n)) sub(r2, m, n);
    }

    memset(one, 0, n * sizeof *one);
    one[0] = 1;

    /* table[k] = base^k in Montgomery form. */
    montmul(table[0], one, r2, m, n, m0inv);
    montmul(table[1], b, r2, m, n, m0inv);
    for (int k = 2; k < 16; k++) montmul(table[k], table[k - 1], table[1], m, n, m0inv);

    memcpy(x, table[0], n * sizeof *x);
    for (size_t i = 0; i < exp_len; i++) {
        for (int half = 1; half >= 0; half--) {
            unsigned nibble = (exp[i] >> (4 * half)) & 15;
            for (int s = 0; s < 4; s++) montmul(x, x, x, m, n, m0inv);
            if (nibble) montmul(x, x, table[nibble], m, n, m0inv);
        }
    }
    montmul(x, x, one, m, n, m0inv); /* out of Montgomery form */

    memset(out, 0, mod_len);
    for (size_t i = 0; i < mod_len; i++) {
        size_t bit = (mod_len - 1 - i) * 8;
        out[i] = (uint8_t)(x[bit / 32] >> (bit % 32));
    }
    return 0;
}
