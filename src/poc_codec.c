/*
 * poc_codec.c — Audio codec implementations
 *
 * Speex NB/WB/UWB via libspeex, G.711 PCMU/PCMA via lookup tables,
 * Opus NB/WB/SWB/FB via libopus (optional).
 * All codecs conform to the poc_codec_t vtable interface.
 */

#include "poc_internal.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_OPUS
#include <opus/opus.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ── G.711 lookup tables ───────────────────────────────────────────
 *
 * ITU-T G.711: 16-bit linear PCM ↔ 8-bit companded (μ-law / A-law).
 * Tables generated from the standard formulas.
 */

/* μ-law constants */
#define ULAW_BIAS   0x84   /* 132 */
#define ULAW_CLIP   32635

static uint8_t pcm16_to_ulaw(int16_t pcm)
{
    int sign = (pcm >> 8) & 0x80;
    if (sign)
        pcm = -pcm;
    if (pcm > ULAW_CLIP)
        pcm = ULAW_CLIP;
    pcm += ULAW_BIAS;

    int exponent = 7;
    for (int mask = 0x4000; !(pcm & mask) && exponent > 0; exponent--, mask >>= 1)
        ;

    int mantissa = (pcm >> (exponent + 3)) & 0x0F;
    uint8_t ulawbyte = ~(sign | (exponent << 4) | mantissa);
    return ulawbyte;
}

static int16_t ulaw_to_pcm16(uint8_t ulaw)
{
    ulaw = ~ulaw;
    int sign = ulaw & 0x80;
    int exponent = (ulaw >> 4) & 0x07;
    int mantissa = ulaw & 0x0F;
    int sample = ((mantissa << 3) + ULAW_BIAS) << exponent;
    sample -= ULAW_BIAS;
    return (int16_t)(sign ? -sample : sample);
}

static uint8_t pcm16_to_alaw(int16_t pcm_in)
{
    int sign = 0;
    int pcm = pcm_in;
    if (pcm < 0) {
        sign = 0x80;
        pcm = -pcm;
    }
    if (pcm > 32767)
        pcm = 32767;

    int exponent = 7;
    for (int mask = 0x4000; !(pcm & mask) && exponent > 0; exponent--, mask >>= 1)
        ;

    int mantissa;
    if (exponent > 1)
        mantissa = (pcm >> (exponent + 3)) & 0x0F;
    else
        mantissa = (pcm >> 4) & 0x0F;

    uint8_t alawbyte = (uint8_t)(sign | (exponent << 4) | mantissa);
    return alawbyte ^ 0x55;
}

static int16_t alaw_to_pcm16(uint8_t alaw)
{
    alaw ^= 0x55;
    int sign = alaw & 0x80;
    int exponent = (alaw >> 4) & 0x07;
    int mantissa = alaw & 0x0F;

    int sample;
    if (exponent > 1)
        sample = ((mantissa << 3) + 0x84) << (exponent - 1);
    else if (exponent == 1)
        sample = (mantissa << 4) + 0x84;
    else
        sample = (mantissa << 4) + 8;

    return (int16_t)(sign ? -sample : sample);
}

/* ── Speex codec ───────────────────────────────────────────────── */

typedef struct {
    poc_codec_t  base;
    void        *enc_state;
    void        *dec_state;
    SpeexBits    enc_bits;
    SpeexBits    dec_bits;
} poc_speex_codec_t;

static int spx_encode(poc_codec_t *c, const int16_t *pcm, int n_samples,
                        uint8_t *out, int out_max)
{
    poc_speex_codec_t *s = (poc_speex_codec_t *)c;
    (void)n_samples;

    speex_bits_reset(&s->enc_bits);
    speex_encode_int(s->enc_state, (spx_int16_t *)pcm, &s->enc_bits);

    int nbytes = speex_bits_write(&s->enc_bits, (char *)out, out_max);
    return nbytes;
}

static int spx_decode(poc_codec_t *c, const uint8_t *in, int in_len,
                           int16_t *pcm, int pcm_max)
{
    poc_speex_codec_t *s = (poc_speex_codec_t *)c;
    (void)pcm_max;

    speex_bits_read_from(&s->dec_bits, (const char *)in, in_len);

    int rc = speex_decode_int(s->dec_state, &s->dec_bits, (spx_int16_t *)pcm);
    if (rc < 0)
        return rc;

    return c->frame_samples;
}

static void spx_destroy(poc_codec_t *c)
{
    poc_speex_codec_t *s = (poc_speex_codec_t *)c;
    if (s->enc_state) {
        speex_encoder_destroy(s->enc_state);
        speex_bits_destroy(&s->enc_bits);
    }
    if (s->dec_state) {
        speex_decoder_destroy(s->dec_state);
        speex_bits_destroy(&s->dec_bits);
    }
    free(s);
}

static poc_codec_t *create_speex(int codec_type, const SpeexMode *mode,
                                 int sample_rate, int max_enc)
{
    poc_speex_codec_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->enc_state = speex_encoder_init(mode);
    if (!s->enc_state) { free(s); return NULL; }

    int quality = 4;
    speex_encoder_ctl(s->enc_state, SPEEX_SET_QUALITY, &quality);

    int frame_size = 0;
    speex_encoder_ctl(s->enc_state, SPEEX_GET_FRAME_SIZE, &frame_size);
    speex_bits_init(&s->enc_bits);

    s->dec_state = speex_decoder_init(mode);
    if (!s->dec_state) {
        speex_encoder_destroy(s->enc_state);
        free(s);
        return NULL;
    }
    speex_bits_init(&s->dec_bits);

    s->base.encode = spx_encode;
    s->base.decode = spx_decode;
    s->base.destroy = spx_destroy;
    s->base.sample_rate = sample_rate;
    s->base.frame_samples = frame_size;
    s->base.frame_ms = 20;
    s->base.max_encoded_size = max_enc;
    s->base.codec_type = codec_type;

    poc_log("codec: speex init (rate=%d, frame=%d, max_enc=%d)",
            sample_rate, frame_size, max_enc);
    return &s->base;
}

/* ── G.711 PCMU codec ──────────────────────────────────────────── */

typedef struct {
    poc_codec_t base;
} poc_g711_codec_t;

static int pcmu_encode(poc_codec_t *c, const int16_t *pcm, int n_samples,
                       uint8_t *out, int out_max)
{
    (void)c;
    if (out_max < n_samples) return -1;
    for (int i = 0; i < n_samples; i++)
        out[i] = pcm16_to_ulaw(pcm[i]);
    return n_samples;
}

static int pcmu_decode(poc_codec_t *c, const uint8_t *in, int in_len,
                       int16_t *pcm, int pcm_max)
{
    (void)c;
    if (pcm_max < in_len) return -1;
    for (int i = 0; i < in_len; i++)
        pcm[i] = ulaw_to_pcm16(in[i]);
    return in_len;
}

/* ── G.711 PCMA codec ──────────────────────────────────────────── */

static int pcma_encode(poc_codec_t *c, const int16_t *pcm, int n_samples,
                       uint8_t *out, int out_max)
{
    (void)c;
    if (out_max < n_samples) return -1;
    for (int i = 0; i < n_samples; i++)
        out[i] = pcm16_to_alaw(pcm[i]);
    return n_samples;
}

static int pcma_decode(poc_codec_t *c, const uint8_t *in, int in_len,
                       int16_t *pcm, int pcm_max)
{
    (void)c;
    if (pcm_max < in_len) return -1;
    for (int i = 0; i < in_len; i++)
        pcm[i] = alaw_to_pcm16(in[i]);
    return in_len;
}

static void g711_destroy(poc_codec_t *c)
{
    free(c);
}

static poc_codec_t *create_g711(int codec_type, int (*enc)(poc_codec_t *, const int16_t *, int, uint8_t *, int),
                                int (*dec)(poc_codec_t *, const uint8_t *, int, int16_t *, int))
{
    poc_g711_codec_t *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->base.encode = enc;
    g->base.decode = dec;
    g->base.destroy = g711_destroy;
    g->base.sample_rate = 8000;
    g->base.frame_samples = 160;
    g->base.frame_ms = 20;
    g->base.max_encoded_size = 160;  /* 1:1 ratio */
    g->base.codec_type = codec_type;

    poc_log("codec: g711 init (type=%s)", codec_type == POC_CODEC_PCMU ? "PCMU" : "PCMA");
    return &g->base;
}

/* ── Opus codec (optional) ──────────────────────────────────────── */

#ifdef HAVE_OPUS

#define OPUS_MAX_ENC  256   /* conservative max for voice bitrates */

typedef struct {
    poc_codec_t   base;
    OpusEncoder  *enc;
    OpusDecoder  *dec;
} poc_opus_codec_t;

static int opus_enc(poc_codec_t *c, const int16_t *pcm, int n_samples,
                    uint8_t *out, int out_max)
{
    poc_opus_codec_t *o = (poc_opus_codec_t *)c;
    int nbytes = opus_encode(o->enc, pcm, n_samples, out, out_max);
    return nbytes > 0 ? nbytes : -1;
}

static int opus_dec(poc_codec_t *c, const uint8_t *in, int in_len,
                    int16_t *pcm, int pcm_max)
{
    poc_opus_codec_t *o = (poc_opus_codec_t *)c;
    int samples = opus_decode(o->dec, in, in_len, pcm, pcm_max, 0);
    return samples > 0 ? samples : -1;
}

static void opus_destroy_fn(poc_codec_t *c)
{
    poc_opus_codec_t *o = (poc_opus_codec_t *)c;
    if (o->enc) opus_encoder_destroy(o->enc);
    if (o->dec) opus_decoder_destroy(o->dec);
    free(o);
}

static poc_codec_t *create_opus(int codec_type, int sample_rate)
{
    poc_opus_codec_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;

    int err;
    o->enc = opus_encoder_create(sample_rate, 1, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !o->enc) { free(o); return NULL; }

    o->dec = opus_decoder_create(sample_rate, 1, &err);
    if (err != OPUS_OK || !o->dec) {
        opus_encoder_destroy(o->enc);
        free(o);
        return NULL;
    }

    /* Voice bitrate — Opus auto-adjusts around this target */
    opus_int32 bitrate = 24000;
    opus_encoder_ctl(o->enc, OPUS_SET_BITRATE(bitrate));

    int frame_samples = sample_rate / 50;  /* 20ms */

    o->base.encode = opus_enc;
    o->base.decode = opus_dec;
    o->base.destroy = opus_destroy_fn;
    o->base.sample_rate = sample_rate;
    o->base.frame_samples = frame_samples;
    o->base.frame_ms = 20;
    o->base.max_encoded_size = OPUS_MAX_ENC;
    o->base.codec_type = codec_type;

    poc_log("codec: opus init (rate=%d, frame=%d)", sample_rate, frame_samples);
    return &o->base;
}

/*
 * Opus 32kHz variant — caller provides 32kHz PCM (640 samples/20ms),
 * we resample to 48kHz (960 samples) for Opus, and back on decode.
 * Simple linear interpolation is sufficient for voice.
 */

/* Upsample 32kHz → 48kHz (ratio 2:3) using linear interpolation */
static void resample_32k_to_48k(const int16_t *in, int in_n,
                                int16_t *out, int out_n)
{
    (void)out_n;
    for (int i = 0; i < out_n; i++) {
        /* Map output sample position back to input position */
        float src = (float)i * (float)(in_n - 1) / (float)(out_n - 1);
        int idx = (int)src;
        float frac = src - idx;
        if (idx >= in_n - 1)
            out[i] = in[in_n - 1];
        else
            out[i] = (int16_t)(in[idx] * (1.0f - frac) + in[idx + 1] * frac);
    }
}

/* Downsample 48kHz → 32kHz (ratio 3:2) using linear interpolation */
static void resample_48k_to_32k(const int16_t *in, int in_n,
                                int16_t *out, int out_n)
{
    (void)out_n;
    for (int i = 0; i < out_n; i++) {
        float src = (float)i * (float)(in_n - 1) / (float)(out_n - 1);
        int idx = (int)src;
        float frac = src - idx;
        if (idx >= in_n - 1)
            out[i] = in[in_n - 1];
        else
            out[i] = (int16_t)(in[idx] * (1.0f - frac) + in[idx + 1] * frac);
    }
}

typedef struct {
    poc_codec_t   base;
    OpusEncoder  *enc;
    OpusDecoder  *dec;
    int16_t       enc_buf[960];  /* 48kHz 20ms frame for encoder */
    int16_t       dec_buf[960];  /* 48kHz 20ms frame from decoder */
} poc_opus_32k_codec_t;

static int opus_32k_enc(poc_codec_t *c, const int16_t *pcm, int n_samples,
                        uint8_t *out, int out_max)
{
    poc_opus_32k_codec_t *o = (poc_opus_32k_codec_t *)c;
    /* 640 samples @ 32kHz → 960 samples @ 48kHz */
    resample_32k_to_48k(pcm, n_samples, o->enc_buf, 960);
    int nbytes = opus_encode(o->enc, o->enc_buf, 960, out, out_max);
    return nbytes > 0 ? nbytes : -1;
}

static int opus_32k_dec(poc_codec_t *c, const uint8_t *in, int in_len,
                        int16_t *pcm, int pcm_max)
{
    poc_opus_32k_codec_t *o = (poc_opus_32k_codec_t *)c;
    (void)pcm_max;
    /* Decode to 960 samples @ 48kHz */
    int samples = opus_decode(o->dec, in, in_len, o->dec_buf, 960, 0);
    if (samples <= 0) return -1;
    /* 960 samples @ 48kHz → 640 samples @ 32kHz */
    resample_48k_to_32k(o->dec_buf, samples, pcm, 640);
    return 640;
}

static void opus_32k_destroy(poc_codec_t *c)
{
    poc_opus_32k_codec_t *o = (poc_opus_32k_codec_t *)c;
    if (o->enc) opus_encoder_destroy(o->enc);
    if (o->dec) opus_decoder_destroy(o->dec);
    free(o);
}

static poc_codec_t *create_opus_32k(int codec_type)
{
    poc_opus_32k_codec_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;

    int err;
    o->enc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !o->enc) { free(o); return NULL; }

    o->dec = opus_decoder_create(48000, 1, &err);
    if (err != OPUS_OK || !o->dec) {
        opus_encoder_destroy(o->enc);
        free(o);
        return NULL;
    }

    opus_int32 bitrate = 24000;
    opus_encoder_ctl(o->enc, OPUS_SET_BITRATE(bitrate));

    o->base.encode = opus_32k_enc;
    o->base.decode = opus_32k_dec;
    o->base.destroy = opus_32k_destroy;
    o->base.sample_rate = 32000;
    o->base.frame_samples = 640;  /* 20ms @ 32kHz */
    o->base.frame_ms = 20;
    o->base.max_encoded_size = OPUS_MAX_ENC;
    o->base.codec_type = codec_type;

    poc_log("codec: opus 32k init (32kHz↔48kHz resample, frame=640)");
    return &o->base;
}

#endif /* HAVE_OPUS */

/* ── Factory ───────────────────────────────────────────────────── */

poc_codec_t *poc_codec_create(int codec_type)
{
    switch (codec_type) {
    case POC_CODEC_SPEEX_NB:
        return create_speex(codec_type, &speex_nb_mode, 8000, 64);
    case POC_CODEC_SPEEX_WB:
        return create_speex(codec_type, &speex_wb_mode, 16000, 128);
    case POC_CODEC_SPEEX_UWB:
        return create_speex(codec_type, &speex_uwb_mode, 32000, 192);
    case POC_CODEC_PCMU:
        return create_g711(codec_type, pcmu_encode, pcmu_decode);
    case POC_CODEC_PCMA:
        return create_g711(codec_type, pcma_encode, pcma_decode);
#ifdef HAVE_OPUS
    case POC_CODEC_OPUS_NB:
        return create_opus(codec_type, 8000);
    case POC_CODEC_OPUS_WB:
        return create_opus(codec_type, 16000);
    case POC_CODEC_OPUS_SWB:
        return create_opus(codec_type, 24000);
    case POC_CODEC_OPUS_FB:
        return create_opus(codec_type, 48000);
    case POC_CODEC_OPUS_32K:
        return create_opus_32k(codec_type);
#endif
    default:
        return NULL;
    }
}

/* ── Codec availability query ──────────────────────────────────── */

bool poc_codec_available(int codec_type)
{
    switch (codec_type) {
    case POC_CODEC_SPEEX_NB:
    case POC_CODEC_SPEEX_WB:
    case POC_CODEC_SPEEX_UWB:
    case POC_CODEC_PCMU:
    case POC_CODEC_PCMA:
        return true;
    case POC_CODEC_OPUS_NB:
    case POC_CODEC_OPUS_WB:
    case POC_CODEC_OPUS_SWB:
    case POC_CODEC_OPUS_FB:
    case POC_CODEC_OPUS_32K:
#ifdef HAVE_OPUS
        return true;
#else
        return false;
#endif
    default:
        return false;
    }
}
