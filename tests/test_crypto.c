/*
 * test_crypto.c — Tests for SHA1 and HMAC-SHA1
 */

#include "poc_internal.h"
#include <string.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_crypto(void)
{
    /* SHA1 of empty string */
    {
        test_begin("SHA1 of empty string");
        char hex[41];
        poc_sha1("", hex);
        test_assert(strcmp(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0,
                    "known hash of ''");
    }

    /* SHA1 of "password" */
    {
        test_begin("SHA1 of 'password'");
        char hex[41];
        poc_sha1("password", hex);
        test_assert(strcmp(hex, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8") == 0,
                    "known hash of 'password'");
    }

    /* SHA1 of "123456" (common PoC radio password) */
    {
        test_begin("SHA1 of '123456'");
        char hex[41];
        poc_sha1("123456", hex);
        test_assert(strcmp(hex, "7c4a8d09ca3762af61e59520943dc26494f8941b") == 0,
                    "known hash");
    }

    /* SHA1 output is always 40 hex chars + null */
    {
        test_begin("SHA1 output length is 40");
        char hex[41];
        poc_sha1("test", hex);
        test_assert(strlen(hex) == 40, "should be 40 hex chars");
    }

    /* SHA1 output is lowercase hex */
    {
        test_begin("SHA1 output is lowercase hex");
        char hex[41];
        poc_sha1("test", hex);
        int ok = 1;
        for (int i = 0; i < 40; i++) {
            if (!((hex[i] >= '0' && hex[i] <= '9') ||
                  (hex[i] >= 'a' && hex[i] <= 'f'))) {
                ok = 0;
                break;
            }
        }
        test_assert(ok, "all chars should be [0-9a-f]");
    }

    /* HMAC-SHA1 RFC 2202 test vector 1 */
    {
        test_begin("HMAC-SHA1 RFC 2202 test vector 1");
        /* Key = 0x0b repeated 20 times, Data = "Hi There" */
        uint8_t key[20];
        memset(key, 0x0b, 20);
        const uint8_t *data = (const uint8_t *)"Hi There";
        uint8_t digest[20];
        poc_hmac_sha1(key, 20, data, 8, digest);

        uint8_t expected[] = {
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
            0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
            0xf1, 0x46, 0xbe, 0x00
        };
        test_assert(memcmp(digest, expected, 20) == 0, "digest mismatch");
    }

    /* HMAC-SHA1 RFC 2202 test vector 2 */
    {
        test_begin("HMAC-SHA1 RFC 2202 test vector 2");
        /* Key = "Jefe", Data = "what do ya want for nothing?" */
        uint8_t digest[20];
        poc_hmac_sha1((const uint8_t *)"Jefe", 4,
                      (const uint8_t *)"what do ya want for nothing?", 28,
                      digest);

        uint8_t expected[] = {
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
            0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
            0x25, 0x9a, 0x7c, 0x79
        };
        test_assert(memcmp(digest, expected, 20) == 0, "digest mismatch");
    }

    /* HMAC-SHA1 with PoC-style usage: 40-byte hex key + 4-byte nonce */
    {
        test_begin("HMAC-SHA1 PoC login pattern");
        /* Simulate: key = SHA1("password") hex, data = 4-byte nonce */
        char sha1_hex[41];
        poc_sha1("password", sha1_hex);

        uint8_t nonce[4];
        poc_write32(nonce, 0x12345678);

        uint8_t digest[20];
        poc_hmac_sha1((const uint8_t *)sha1_hex, 40, nonce, 4, digest);

        /* Just verify it produces 20 bytes without crashing */
        int nonzero = 0;
        for (int i = 0; i < 20; i++)
            if (digest[i]) nonzero++;
        test_assert(nonzero > 0, "digest should not be all zeros");
    }
}
