/* SPDX-License-Identifier: MIT */

#ifndef RVNC_DES_H
#define RVNC_DES_H

#include <stddef.h>
#include <stdint.h>

/* DES encryption (FIPS 46-3), ECB, for the VNC password and UltraVNC MS-Logon II logins.
 * Single DES is long broken; these logins only use it because the protocols require it.
 * No global state: calls may run on several threads at once. in and out may be the same
 * buffer; both hold blocks * 8 bytes. The key schedule is wiped before returning. */

/* Standard DES: key bytes as in FIPS 46-3 (the low bit of each byte is the unused parity bit). */
void rvnc_des_ecb_encrypt(const uint8_t key[8], const uint8_t *in, uint8_t *out, size_t blocks);

/* VNC's convention: the bits of each key byte are reversed first, so the high bit of each
 * password byte is the one ignored. Used by VNC authentication (RFB security type 2) and
 * MS-Logon II. */
void rvnc_des_vnc_encrypt(const uint8_t key[8], const uint8_t *in, uint8_t *out, size_t blocks);

#endif
