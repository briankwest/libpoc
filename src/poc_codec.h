/*
 * poc_codec.h — Audio codec abstraction layer
 *
 * Vtable-style interface for pluggable audio codecs.
 * Each codec embeds poc_codec_t as its first member and
 * provides encode/decode/destroy via function pointers.
 *
 * Supported codecs:
 *   Speex NB   (8kHz, 160 samples/frame, ~20 bytes encoded)
 *   Speex WB   (16kHz, 320 samples/frame, ~46 bytes encoded)
 *   Speex UWB  (32kHz, 640 samples/frame, ~70 bytes encoded)
 *   G.711 PCMU (8kHz, 160 samples/frame, 160 bytes encoded)
 *   G.711 PCMA (8kHz, 160 samples/frame, 160 bytes encoded)
 */

#ifndef POC_CODEC_H
#define POC_CODEC_H

#include <stdint.h>

/* Maximum frame size across all supported codecs.
 * Sized for 48kHz at 20ms (future Opus support). */
#define POC_CODEC_MAX_FRAME_SAMPLES  960
#define POC_CODEC_MAX_ENCODED_SIZE   960   /* PCMU worst case = 1:1 */

typedef struct poc_codec poc_codec_t;

struct poc_codec {
    /*
     * Encode one frame of PCM → compressed bytes.
     * Returns number of bytes written to `out`, or < 0 on error.
     */
    int  (*encode)(poc_codec_t *c, const int16_t *pcm, int n_samples,
                   uint8_t *out, int out_max);

    /*
     * Decode compressed bytes → one frame of PCM.
     * Returns number of samples written to `pcm`, or < 0 on error.
     */
    int  (*decode)(poc_codec_t *c, const uint8_t *in, int in_len,
                   int16_t *pcm, int pcm_max);

    /*
     * Free codec resources. Called by poc_codec_destroy().
     */
    void (*destroy)(poc_codec_t *c);

    int  sample_rate;       /* Hz: 8000, 16000, 32000, 48000 */
    int  frame_samples;     /* samples per frame */
    int  frame_ms;          /* ms per frame (always 20) */
    int  max_encoded_size;  /* worst-case encoded bytes per frame */
    int  codec_type;        /* POC_CODEC_* enum value */
};

/*
 * Create a codec instance for the given type (POC_CODEC_* enum).
 * Returns NULL on invalid type or allocation failure.
 */
poc_codec_t *poc_codec_create(int codec_type);

/*
 * Destroy a codec instance. Safe to call with NULL.
 */
static inline void poc_codec_destroy(poc_codec_t *c)
{
    if (c && c->destroy)
        c->destroy(c);
}

/* Convenience wrappers */

static inline int poc_codec_encode(poc_codec_t *c, const int16_t *pcm,
                                   int n_samples, uint8_t *out, int out_max)
{
    return c->encode(c, pcm, n_samples, out, out_max);
}

static inline int poc_codec_decode(poc_codec_t *c, const uint8_t *in,
                                   int in_len, int16_t *pcm, int pcm_max)
{
    return c->decode(c, in, in_len, pcm, pcm_max);
}

#endif /* POC_CODEC_H */
