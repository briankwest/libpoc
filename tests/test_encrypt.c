/*
 * test_encrypt.c — Tests for audio encryption/decryption
 */

#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_encrypt(void)
{
    poc_encrypt_t enc;

    {
        test_begin("encrypt: init sets disabled");
        poc_encrypt_init(&enc);
        test_assert(!enc.enabled, "should be disabled");
    }

    {
        test_begin("encrypt: set_key enables encryption");
        uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        poc_encrypt_set_key(&enc, POC_KEY_TYPE_AES, key, 16);
        test_assert(enc.enabled, "should be enabled");
        test_assert(enc.key_type == POC_KEY_TYPE_AES, "type=AES");
        test_assert(enc.key_len == 16, "key_len=16");
    }

    /* AES roundtrip */
    {
        test_begin("encrypt: AES encrypt/decrypt roundtrip");
        uint8_t plaintext[20] = "hello poc audio!!!!";
        uint8_t ciphertext[48];
        uint8_t decrypted[48];

        int elen = poc_encrypt_audio(&enc, 0, plaintext, 20, ciphertext, sizeof(ciphertext));
        test_assert(elen > 0, "encrypt should produce output");
    }

    {
        test_begin("encrypt: AES ciphertext differs from plaintext");
        uint8_t plaintext[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        uint8_t ciphertext[48];

        int elen = poc_encrypt_audio(&enc, 0, plaintext, 16, ciphertext, sizeof(ciphertext));
        test_assert(elen > 0 && memcmp(plaintext, ciphertext, 16) != 0,
                    "ciphertext should differ");
    }

    {
        test_begin("encrypt: AES decrypt recovers plaintext");
        uint8_t plaintext[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        uint8_t ciphertext[48], decrypted[48];

        int elen = poc_encrypt_audio(&enc, 0, plaintext, 16, ciphertext, sizeof(ciphertext));
        int dlen = poc_decrypt_audio(&enc, 0, ciphertext, elen, decrypted, sizeof(decrypted));
        test_assert(dlen == 16 && memcmp(plaintext, decrypted, 16) == 0,
                    "roundtrip should match");
    }

    /* Per-group keys */
    {
        test_begin("encrypt: group key overrides session key");
        uint8_t gkey[16] = {99,98,97,96,95,94,93,92,91,90,89,88,87,86,85,84};
        poc_encrypt_set_group_key(&enc, 42, POC_KEY_TYPE_AES, gkey, 16);

        uint8_t plaintext[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t ct_session[48], ct_group[48];

        /* Encrypt with session key (group 0) */
        poc_encrypt_audio(&enc, 0, plaintext, 16, ct_session, sizeof(ct_session));
        /* Encrypt with group key (group 42) */
        poc_encrypt_audio(&enc, 42, plaintext, 16, ct_group, sizeof(ct_group));

        test_assert(memcmp(ct_session, ct_group, 16) != 0,
                    "different keys should produce different ciphertext");
    }

    {
        test_begin("encrypt: group key decrypt works");
        uint8_t plaintext[16] = {10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160};
        uint8_t ciphertext[48], decrypted[48];

        int elen = poc_encrypt_audio(&enc, 42, plaintext, 16, ciphertext, sizeof(ciphertext));
        int dlen = poc_decrypt_audio(&enc, 42, ciphertext, elen, decrypted, sizeof(decrypted));
        test_assert(dlen == 16 && memcmp(plaintext, decrypted, 16) == 0,
                    "group key roundtrip");
    }

    /* Disabled encryption returns error */
    {
        test_begin("encrypt: disabled returns error");
        poc_encrypt_t disabled;
        poc_encrypt_init(&disabled);
        uint8_t buf[32];
        int rc = poc_encrypt_audio(&disabled, 0, buf, 16, buf, 32);
        test_assert(rc == -1, "should fail when disabled");
    }

    {
        test_begin("encrypt: destroy clears key");
        poc_encrypt_destroy(&enc);
        test_assert(!enc.enabled, "should be disabled after destroy");
    }
}
