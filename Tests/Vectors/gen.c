/* Prints the expected values in Tests/RoyalVNCKitTests, using DES implementations other than
 * CDES: CommonCrypto (VNC key = bits of each key byte reversed), and LibVNCServer's and
 * LibVNCClient's VNC routines. VNC responses are printed after CommonCrypto, LibVNCServer and
 * LibVNCClient agree; MS-Logon II credentials after CommonCrypto and LibVNCClient agree.
 *
 * macOS with LibVNCServer installed (it ships both libraries), e.g. Homebrew's libvncserver:
 *   cc -Wall -Wextra -Wno-deprecated-declarations Tests/Vectors/gen.c \
 *      -L"$(brew --prefix)/lib" -lvncserver -lvncclient -o /tmp/gen && /tmp/gen
 *
 * Not part of any SwiftPM target. */
#include <CommonCrypto/CommonCryptor.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void rfbEncryptBytes(unsigned char *bytes, char *passwd);                          /* LibVNCServer */
extern void rfbClientEncryptBytes(unsigned char *bytes, char *passwd);                    /* LibVNCClient */
extern void rfbClientEncryptBytes2(unsigned char *where, const int length, unsigned char *key); /* LibVNCClient, MS-Logon II */

static void require(int ok, const char *what) {
    if (!ok) { fprintf(stderr, "oracles disagree: %s\n", what); exit(1); }
}

static void reverse_bits(const uint8_t key[8], uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        out[i] = 0;
        for (int b = 0; b < 8; b++) out[i] |= ((key[i] >> b) & 1) << (7 - b);
    }
}

static void print_hex(const uint8_t *data, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", data[i]);
    printf("\n");
}

/* VNC password response to the challenge 00 01 .. 0f. */
static void vnc_response(const char *password) {
    uint8_t challenge[16], key[8] = {0}, reversed[8], a[16], b[16], c[16];
    size_t n = strlen(password), done = 0;

    for (int i = 0; i < 16; i++) challenge[i] = (uint8_t)i;
    memcpy(key, password, n < 8 ? n : 8);
    reverse_bits(key, reversed);
    require(CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, reversed, 8, NULL,
                    challenge, 16, a, 16, &done) == kCCSuccess && done == 16, "CCCrypt");

    memcpy(b, challenge, 16);
    rfbEncryptBytes(b, (char *)password);
    memcpy(c, challenge, 16);
    rfbClientEncryptBytes(c, (char *)password);
    require(!memcmp(a, b, 16) && !memcmp(a, c, 16), password);

    printf("vnc [%s] ", password);
    print_hex(a, 16);
}

/* One MS-Logon II field: zero-padded or cut to length, DES-CBC with the secret as IV. */
static void mslogon_field(const uint8_t secret[8], const char *text, size_t length, uint8_t *out) {
    uint8_t plain[256] = {0}, reversed[8], key[8], other[256];
    size_t n = strlen(text), done = 0;

    memcpy(plain, text, n < length ? n : length);
    reverse_bits(secret, reversed);
    require(CCCrypt(kCCEncrypt, kCCAlgorithmDES, 0, reversed, 8, secret,
                    plain, length, out, length, &done) == kCCSuccess && done == length, "CCCrypt CBC");

    memcpy(other, plain, length);
    memcpy(key, secret, 8);
    rfbClientEncryptBytes2(other, (int)length, key);
    require(!memcmp(out, other, length), text);
}

static void mslogon_credential(const uint8_t secret[8], const char *username, const char *password) {
    uint8_t credential[320];

    mslogon_field(secret, username, 256, credential);
    mslogon_field(secret, password, 64, credential + 256);

    printf("mslogon [%s] [%s] ", username, password);
    print_hex(credential, 320);
}

int main(void) {
    static const char *passwords[] = {
        "", "a", "1234567", "12345678", "123456789", "password",
        "\xc3\xa9",                                     /* é */
        "C)",                                           /* é with the high bits cleared */
        "p\xc3\xa4ssword", "p\xc3\xa4sswor",
        "abcdefg\xc3\xa9",                              /* abcdefgé */
        "\xf0\x9f\x98\x80\xf0\x9f\x98\x80",             /* two emoji */
        "abcdefg\xf0\x9f\x98\x80",
    };
    for (size_t i = 0; i < sizeof passwords / sizeof *passwords; i++) vnc_response(passwords[i]);

    static const uint8_t secret[8] = {0x3a, 0x91, 0xc4, 0x07, 0x5e, 0xd2, 0x68, 0xbf};
    mslogon_credential(secret, "user", "secret");
    /* "üser", and "pässwörd" six times with spaces: 65 bytes, cut to 64 */
    mslogon_credential(secret, "\xc3\xbcser",
                       "p\xc3\xa4ssw\xc3\xb6rd p\xc3\xa4ssw\xc3\xb6rd p\xc3\xa4ssw\xc3\xb6rd "
                       "p\xc3\xa4ssw\xc3\xb6rd p\xc3\xa4ssw\xc3\xb6rd p\xc3\xa4ssw\xc3\xb6rd");
    return 0;
}
