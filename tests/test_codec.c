/*
 * test_codec.c — Tests for Speex codec wrapper
 */

#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_codec(void)
{
    poc_speex_t spx;

    /* Init */
    {
        test_begin("speex init succeeds");
        int rc = poc_speex_init(&spx);
        test_assert(rc == POC_OK, "init should succeed");
    }

    {
        test_begin("speex frame_size is 160");
        test_assert(spx.frame_size == 160, "narrowband = 160 samples");
    }

    /* Encode silence */
    {
        test_begin("encode silence produces bytes");
        int16_t pcm[160];
        memset(pcm, 0, sizeof(pcm));
        uint8_t encoded[SPEEX_FRAME_ENC];
        int len = poc_speex_encode(&spx, pcm, encoded);
        test_assert(len > 0, "should produce output");
    }

    /* Encode produces consistent length */
    {
        test_begin("encode output is ~20 bytes (mode 4)");
        int16_t pcm[160];
        memset(pcm, 0, sizeof(pcm));
        uint8_t encoded[64];
        int len = poc_speex_encode(&spx, pcm, encoded);
        test_assert(len >= 15 && len <= 25, "should be ~20 bytes");
    }

    /* Decode produces 160 samples */
    {
        test_begin("decode produces 160 samples");
        int16_t pcm_in[160], pcm_out[160];
        memset(pcm_in, 0, sizeof(pcm_in));
        uint8_t encoded[64];
        int enc_len = poc_speex_encode(&spx, pcm_in, encoded);

        int dec_samples = poc_speex_decode(&spx, encoded, enc_len, pcm_out);
        test_assert(dec_samples == 160, "should decode 160 samples");
    }

    /* Roundtrip: encode silence, decode, should be ~silence */
    {
        test_begin("roundtrip silence stays quiet");
        int16_t pcm_in[160], pcm_out[160];
        memset(pcm_in, 0, sizeof(pcm_in));
        uint8_t encoded[64];
        int enc_len = poc_speex_encode(&spx, pcm_in, encoded);
        poc_speex_decode(&spx, encoded, enc_len, pcm_out);

        /* All samples should be near zero */
        int max_abs = 0;
        for (int i = 0; i < 160; i++) {
            int v = abs(pcm_out[i]);
            if (v > max_abs) max_abs = v;
        }
        test_assert(max_abs < 500, "decoded silence should be quiet");
    }

    /* Encode a 1kHz tone, decode, check it's not silence */
    {
        test_begin("roundtrip 1kHz tone is not silent");
        int16_t pcm_in[160], pcm_out[160];
        for (int i = 0; i < 160; i++)
            pcm_in[i] = (int16_t)(16000.0 * sin(2.0 * 3.14159265 * 1000.0 * i / 8000.0));

        uint8_t encoded[64];
        int enc_len = poc_speex_encode(&spx, pcm_in, encoded);
        poc_speex_decode(&spx, encoded, enc_len, pcm_out);

        int max_abs = 0;
        for (int i = 0; i < 160; i++) {
            int v = abs(pcm_out[i]);
            if (v > max_abs) max_abs = v;
        }
        test_assert(max_abs > 1000, "decoded tone should have energy");
    }

    /* Multiple frames don't crash */
    {
        test_begin("encode/decode 100 frames without crash");
        int16_t pcm[160];
        uint8_t enc[64];
        int16_t dec[160];
        int ok = 1;

        for (int f = 0; f < 100; f++) {
            for (int i = 0; i < 160; i++)
                pcm[i] = (int16_t)(8000.0 * sin(2.0 * 3.14159265 * 440.0 * (f * 160 + i) / 8000.0));
            int elen = poc_speex_encode(&spx, pcm, enc);
            int dlen = poc_speex_decode(&spx, enc, elen, dec);
            if (elen <= 0 || dlen != 160) { ok = 0; break; }
        }
        test_assert(ok, "100 frames without error");
    }

    /* Different encoded frames differ */
    {
        test_begin("different inputs produce different encodings");
        int16_t silence[160], tone[160];
        memset(silence, 0, sizeof(silence));
        for (int i = 0; i < 160; i++)
            tone[i] = (int16_t)(16000.0 * sin(2.0 * 3.14159265 * 1000.0 * i / 8000.0));

        uint8_t enc1[64], enc2[64];
        int len1 = poc_speex_encode(&spx, silence, enc1);
        int len2 = poc_speex_encode(&spx, tone, enc2);

        int differ = (len1 != len2) || memcmp(enc1, enc2, len1 < len2 ? len1 : len2);
        test_assert(differ, "silence and tone should differ");
    }

    /* Cleanup */
    {
        test_begin("speex destroy doesn't crash");
        poc_speex_destroy(&spx);
        test_assert(spx.enc_state == NULL && spx.dec_state == NULL, "cleaned up");
    }

    /* Double destroy is safe */
    {
        test_begin("double destroy is safe");
        poc_speex_destroy(&spx);
        test_end();
    }
}
