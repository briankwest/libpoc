/*
 * poc_encrypt.c — Audio encryption/decryption layer
 *
 * AES-ECB encryption (128/192/256 key sizes via OpenSSL EVP).
 *
 * Keys are per-group, delivered in the UserData (0x0B) login response.
 * For private calls, the key is derived from the session.
 *
 * Encryption wraps encoded audio: codec encode -> encrypt -> UDP send
 * Decryption unwraps on receive: UDP recv -> decrypt -> codec decode
 */

#include "poc_internal.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>

void poc_encrypt_init(poc_encrypt_t *enc)
{
    memset(enc, 0, sizeof(*enc));
    enc->enabled = false;
    enc->key_type = 0;
}

void poc_encrypt_destroy(poc_encrypt_t *enc)
{
    memset(enc->key, 0, sizeof(enc->key));
    enc->enabled = false;
}

void poc_encrypt_set_key(poc_encrypt_t *enc, uint8_t key_type,
                         const uint8_t *key, int key_len)
{
    enc->key_type = key_type;
    int copy = key_len < POC_ENCRYPT_KEY_LEN ? key_len : POC_ENCRYPT_KEY_LEN;
    memcpy(enc->key, key, copy);
    enc->key_len = copy;
    enc->enabled = true;

    poc_log("encrypt: key set, type=0x%02x len=%d", key_type, copy);
}

void poc_encrypt_set_group_key(poc_encrypt_t *enc, uint32_t group_id,
                               uint8_t key_type, const uint8_t *key, int key_len)
{
    /* Store per-group key */
    for (int i = 0; i < POC_MAX_GROUP_KEYS; i++) {
        if (enc->group_keys[i].group_id == group_id || enc->group_keys[i].group_id == 0) {
            enc->group_keys[i].group_id = group_id;
            enc->group_keys[i].key_type = key_type;
            int copy = key_len < POC_ENCRYPT_KEY_LEN ? key_len : POC_ENCRYPT_KEY_LEN;
            memcpy(enc->group_keys[i].key, key, copy);
            enc->group_keys[i].key_len = copy;
            enc->group_keys[i].valid = true;
            poc_log("encrypt: group key set for group=%u type=0x%02x", group_id, key_type);
            return;
        }
    }
    poc_log("encrypt: no room for group key, group=%u", group_id);
}

static const poc_group_key_t *find_group_key(const poc_encrypt_t *enc, uint32_t group_id)
{
    for (int i = 0; i < POC_MAX_GROUP_KEYS; i++) {
        if (enc->group_keys[i].group_id == group_id && enc->group_keys[i].valid)
            return &enc->group_keys[i];
    }
    return NULL;
}

/*
 * AES-128-ECB encrypt/decrypt. Pads to 16-byte boundary.
 * Returns output length, or -1 on error.
 */
static int aes_ecb_crypt(const uint8_t *key, int key_len,
                         const uint8_t *in, int in_len,
                         uint8_t *out, int encrypt)
{
    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!evp) return -1;

    const EVP_CIPHER *cipher = (key_len >= 32) ? EVP_aes_256_ecb() :
                               (key_len >= 24) ? EVP_aes_192_ecb() :
                                                 EVP_aes_128_ecb();

    EVP_CipherInit_ex(evp, cipher, NULL, key, NULL, encrypt);
    EVP_CIPHER_CTX_set_padding(evp, 1);

    int out_len = 0, final_len = 0;
    EVP_CipherUpdate(evp, out, &out_len, in, in_len);
    EVP_CipherFinal_ex(evp, out + out_len, &final_len);
    EVP_CIPHER_CTX_free(evp);

    return out_len + final_len;
}

int poc_encrypt_audio(poc_encrypt_t *enc, uint32_t group_id,
                      const uint8_t *in, int in_len,
                      uint8_t *out, int out_max)
{
    if (!enc->enabled)
        return -1;

    /* Find the key: group key first, then session key */
    const uint8_t *key;
    int key_len;
    uint8_t key_type;

    const poc_group_key_t *gk = find_group_key(enc, group_id);
    if (gk) {
        key = gk->key;
        key_len = gk->key_len;
        key_type = gk->key_type;
    } else {
        key = enc->key;
        key_len = enc->key_len;
        key_type = enc->key_type;
    }

    if (key_len == 0)
        return -1;

    /* Ensure output buffer is large enough (ECB pads to block boundary) */
    int padded = ((in_len + 15) / 16) * 16 + 16; /* max with PKCS padding */
    if (out_max < padded)
        return -1;

    (void)key_type;
    return aes_ecb_crypt(key, key_len, in, in_len, out, 1);
}

int poc_decrypt_audio(poc_encrypt_t *enc, uint32_t group_id,
                      const uint8_t *in, int in_len,
                      uint8_t *out, int out_max)
{
    if (!enc->enabled)
        return -1;

    const uint8_t *key;
    int key_len;
    uint8_t key_type;

    const poc_group_key_t *gk = find_group_key(enc, group_id);
    if (gk) {
        key = gk->key;
        key_len = gk->key_len;
        key_type = gk->key_type;
    } else {
        key = enc->key;
        key_len = enc->key_len;
        key_type = enc->key_type;
    }

    if (key_len == 0 || out_max < in_len)
        return -1;

    (void)key_type;
    return aes_ecb_crypt(key, key_len, in, in_len, out, 0);
}
