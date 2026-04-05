/*
 * test_codec.c — Tests for audio codec abstraction layer
 *
 * Tests all codecs through the poc_codec_t vtable interface:
 * Speex NB/WB/UWB, G.711 PCMU, G.711 PCMA, Opus NB/WB/SWB/FB.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

/* Helper: generate a tone at the given frequency and sample rate */
static void gen_tone(int16_t *pcm, int n_samples, int sample_rate, float freq)
{
    for (int i = 0; i < n_samples; i++)
        pcm[i] = (int16_t)(16000.0 * sin(2.0 * 3.14159265 * freq * i / sample_rate));
}

/* Helper: compute max absolute value */
static int max_abs(const int16_t *pcm, int n)
{
    int m = 0;
    for (int i = 0; i < n; i++) {
        int v = abs(pcm[i]);
        if (v > m) m = v;
    }
    return m;
}

/* ── Generic codec tests (run for every codec type) ────────────── */

static void test_codec_type(int codec_type, const char *name,
                            int expected_rate, int expected_frame)
{
    char desc[80];

    /* Create */
    snprintf(desc, sizeof(desc), "%s: create succeeds", name);
    test_begin(desc);
    poc_codec_t *c = poc_codec_create(codec_type);
    test_assert(c != NULL, "should not be NULL");

    /* Sample rate */
    snprintf(desc, sizeof(desc), "%s: sample_rate = %d", name, expected_rate);
    test_begin(desc);
    test_assert(c->sample_rate == expected_rate, "rate mismatch");

    /* Frame samples */
    snprintf(desc, sizeof(desc), "%s: frame_samples = %d", name, expected_frame);
    test_begin(desc);
    test_assert(c->frame_samples == expected_frame, "frame mismatch");

    /* Frame ms */
    snprintf(desc, sizeof(desc), "%s: frame_ms = 20", name);
    test_begin(desc);
    test_assert(c->frame_ms == 20, "should be 20ms");

    /* max_encoded_size > 0 */
    snprintf(desc, sizeof(desc), "%s: max_encoded_size > 0", name);
    test_begin(desc);
    test_assert(c->max_encoded_size > 0, "should be positive");

    /* Encode silence produces bytes */
    snprintf(desc, sizeof(desc), "%s: encode silence produces bytes", name);
    test_begin(desc);
    int16_t *pcm = calloc(expected_frame, sizeof(int16_t));
    uint8_t encoded[POC_CODEC_MAX_ENCODED_SIZE];
    int enc_len = poc_codec_encode(c, pcm, expected_frame, encoded, sizeof(encoded));
    test_assert(enc_len > 0, "should produce output");

    /* Decode produces expected samples */
    snprintf(desc, sizeof(desc), "%s: decode produces %d samples", name, expected_frame);
    test_begin(desc);
    int16_t *pcm_out = calloc(expected_frame, sizeof(int16_t));
    int dec_samples = poc_codec_decode(c, encoded, enc_len, pcm_out, expected_frame);
    test_assert(dec_samples == expected_frame, "sample count mismatch");

    /* Roundtrip silence stays quiet */
    snprintf(desc, sizeof(desc), "%s: roundtrip silence stays quiet", name);
    test_begin(desc);
    test_assert(max_abs(pcm_out, expected_frame) < 500, "decoded silence should be quiet");

    /* Roundtrip 1kHz tone has energy */
    snprintf(desc, sizeof(desc), "%s: roundtrip tone has energy", name);
    test_begin(desc);
    gen_tone(pcm, expected_frame, expected_rate, 1000.0f);
    enc_len = poc_codec_encode(c, pcm, expected_frame, encoded, sizeof(encoded));
    dec_samples = poc_codec_decode(c, encoded, enc_len, pcm_out, expected_frame);
    test_assert(dec_samples == expected_frame && max_abs(pcm_out, expected_frame) > 1000,
                "decoded tone should have energy");

    /* 100-frame stress test */
    snprintf(desc, sizeof(desc), "%s: 100 frames without crash", name);
    test_begin(desc);
    int ok = 1;
    for (int f = 0; f < 100; f++) {
        gen_tone(pcm, expected_frame, expected_rate, 440.0f);
        int elen = poc_codec_encode(c, pcm, expected_frame, encoded, sizeof(encoded));
        int dlen = poc_codec_decode(c, encoded, elen, pcm_out, expected_frame);
        if (elen <= 0 || dlen != expected_frame) { ok = 0; break; }
    }
    test_assert(ok, "100 frames without error");

    /* Different inputs differ */
    snprintf(desc, sizeof(desc), "%s: different inputs differ", name);
    test_begin(desc);
    memset(pcm, 0, expected_frame * sizeof(int16_t));
    uint8_t enc1[POC_CODEC_MAX_ENCODED_SIZE], enc2[POC_CODEC_MAX_ENCODED_SIZE];
    int len1 = poc_codec_encode(c, pcm, expected_frame, enc1, sizeof(enc1));
    gen_tone(pcm, expected_frame, expected_rate, 1000.0f);
    int len2 = poc_codec_encode(c, pcm, expected_frame, enc2, sizeof(enc2));
    int differ = (len1 != len2) || memcmp(enc1, enc2, len1 < len2 ? len1 : len2);
    test_assert(differ, "silence and tone should differ");

    /* Cleanup */
    snprintf(desc, sizeof(desc), "%s: destroy doesn't crash", name);
    test_begin(desc);
    poc_codec_destroy(c);
    test_end();

    free(pcm);
    free(pcm_out);
}

/* ── PCMU/PCMA specific: known-value tests ─────────────────────── */

static void test_pcmu_known_values(void)
{
    poc_codec_t *c = poc_codec_create(POC_CODEC_PCMU);

    /* PCMU: silence (0) encodes to 0xFF */
    test_begin("PCMU: silence encodes to 0xFF");
    int16_t zero = 0;
    uint8_t enc;
    poc_codec_encode(c, &zero, 1, &enc, 1);
    test_assert(enc == 0xFF, "μ-law silence = 0xFF");

    /* PCMU: encode/decode roundtrip preserves sign */
    test_begin("PCMU: roundtrip preserves sign");
    int16_t pos = 8000, neg = -8000;
    uint8_t enc_pos, enc_neg;
    int16_t dec_pos, dec_neg;
    poc_codec_encode(c, &pos, 1, &enc_pos, 1);
    poc_codec_encode(c, &neg, 1, &enc_neg, 1);
    poc_codec_decode(c, &enc_pos, 1, &dec_pos, 1);
    poc_codec_decode(c, &enc_neg, 1, &dec_neg, 1);
    test_assert(dec_pos > 0 && dec_neg < 0, "sign preserved");

    /* PCMU: 1:1 byte ratio */
    test_begin("PCMU: 160 samples → 160 bytes");
    int16_t pcm[160];
    uint8_t encoded[160];
    memset(pcm, 0, sizeof(pcm));
    int len = poc_codec_encode(c, pcm, 160, encoded, sizeof(encoded));
    test_assert(len == 160, "1:1 ratio");

    poc_codec_destroy(c);
}

static void test_pcma_known_values(void)
{
    poc_codec_t *c = poc_codec_create(POC_CODEC_PCMA);

    /* PCMA: silence (0) encodes to 0x55 (A-law XOR mask) */
    test_begin("PCMA: silence encodes to 0x55");
    int16_t zero = 0;
    uint8_t enc;
    poc_codec_encode(c, &zero, 1, &enc, 1);
    test_assert(enc == 0x55, "A-law silence = 0x55");

    /* PCMA: roundtrip preserves sign */
    test_begin("PCMA: roundtrip preserves sign");
    int16_t pos = 8000, neg = -8000;
    uint8_t enc_pos, enc_neg;
    int16_t dec_pos, dec_neg;
    poc_codec_encode(c, &pos, 1, &enc_pos, 1);
    poc_codec_encode(c, &neg, 1, &enc_neg, 1);
    poc_codec_decode(c, &enc_pos, 1, &dec_pos, 1);
    poc_codec_decode(c, &enc_neg, 1, &dec_neg, 1);
    test_assert(dec_pos > 0 && dec_neg < 0, "sign preserved");

    poc_codec_destroy(c);
}

/* ── Opus-specific tests ───────────────────────────────────────── */

#ifdef HAVE_OPUS
static void test_opus_vbr(void)
{
    poc_codec_t *c = poc_codec_create(POC_CODEC_OPUS_NB);

    /* Opus VBR: silence and tone produce different encoded sizes */
    test_begin("Opus: VBR produces different sizes for silence vs tone");
    int16_t silence[160], tone[160];
    memset(silence, 0, sizeof(silence));
    gen_tone(tone, 160, 8000, 1000.0f);

    uint8_t enc1[256], enc2[256];
    int len1 = poc_codec_encode(c, silence, 160, enc1, sizeof(enc1));
    int len2 = poc_codec_encode(c, tone, 160, enc2, sizeof(enc2));
    test_assert(len1 != len2, "VBR: different content = different sizes");

    /* Opus: encoded size is much smaller than PCM */
    test_begin("Opus: encoded size << PCM size");
    test_assert(len1 < 160 && len2 < 160, "compressed output");

    poc_codec_destroy(c);
}
#endif

/* ── Codec availability tests ──────────────────────────────────── */

static void test_availability(void)
{
    test_begin("available: Speex NB always available");
    test_assert(poc_codec_available(POC_CODEC_SPEEX_NB), "should be true");

    test_begin("available: PCMU always available");
    test_assert(poc_codec_available(POC_CODEC_PCMU), "should be true");

    test_begin("available: invalid type not available");
    test_assert(!poc_codec_available(99), "should be false");

#ifdef HAVE_OPUS
    test_begin("available: Opus NB available (compiled with libopus)");
    test_assert(poc_codec_available(POC_CODEC_OPUS_NB), "should be true");
#else
    test_begin("available: Opus NB not available (no libopus)");
    test_assert(!poc_codec_available(POC_CODEC_OPUS_NB), "should be false");
#endif
}

/* ── Factory edge cases ────────────────────────────────────────── */

static void test_factory(void)
{
    test_begin("factory: invalid type returns NULL");
    poc_codec_t *c = poc_codec_create(99);
    test_assert(c == NULL, "should be NULL");

    test_begin("factory: negative type returns NULL");
    c = poc_codec_create(-1);
    test_assert(c == NULL, "should be NULL");

    test_begin("codec_destroy: NULL is safe");
    poc_codec_destroy(NULL);
    test_end();
}

/* ── Entry point ───────────────────────────────────────────────── */

void test_codec(void)
{
    /* Test all codec types through the generic interface */
    test_codec_type(POC_CODEC_SPEEX_NB,  "Speex NB",  8000,  160);
    test_codec_type(POC_CODEC_SPEEX_WB,  "Speex WB",  16000, 320);
    test_codec_type(POC_CODEC_SPEEX_UWB, "Speex UWB", 32000, 640);
    test_codec_type(POC_CODEC_PCMU,      "PCMU",      8000,  160);
    test_codec_type(POC_CODEC_PCMA,      "PCMA",      8000,  160);

#ifdef HAVE_OPUS
    test_codec_type(POC_CODEC_OPUS_NB,   "Opus NB",   8000,  160);
    test_codec_type(POC_CODEC_OPUS_WB,   "Opus WB",   16000, 320);
    test_codec_type(POC_CODEC_OPUS_SWB,  "Opus SWB",  24000, 480);
    test_codec_type(POC_CODEC_OPUS_FB,   "Opus FB",   48000, 960);
    test_codec_type(POC_CODEC_OPUS_32K,  "Opus 32K",  32000, 640);
#endif

    /* Codec-specific known-value tests */
    test_pcmu_known_values();
    test_pcma_known_values();
#ifdef HAVE_OPUS
    test_opus_vbr();
#endif

    /* Codec availability */
    test_availability();

    /* Factory edge cases */
    test_factory();
}
