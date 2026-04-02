/*
 * poc_crypto.c — SHA1 hash and HMAC-SHA1 for login auth
 */

#include "poc_internal.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdio.h>

void poc_sha1(const char *input, char *hex_out)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)input, strlen(input), digest);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    hex_out[40] = '\0';
}

void poc_hmac_sha1(const uint8_t *key, int key_len,
                   const uint8_t *data, int data_len,
                   uint8_t *digest)
{
    unsigned int out_len = SHA_DIGEST_LENGTH;
    HMAC(EVP_sha1(), key, key_len, data, data_len, digest, &out_len);
}
