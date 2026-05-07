/*
 * poc_codec.h — Audio codec abstraction layer
 *
 * Single codec: Opus super-wideband (24 kHz, 480 samples per 20 ms
 * frame, 32 kbps, inband FEC). The vtable is retained so the encoder
 * and decoder paths can be swapped under test, but production callers
 * just use poc_codec_create() / poc_codec_encode() / poc_codec_decode().
 */

#ifndef POC_CODEC_H
#define POC_CODEC_H

#include <stdint.h>

/* Worst-case encoded packet from the Opus encoder at 32 kbps VBR.
 * Real packets run ~80 bytes; 256 leaves comfortable headroom. */
#define POC_CODEC_MAX_FRAME_SAMPLES  480
#define POC_CODEC_MAX_ENCODED_SIZE   256

typedef struct poc_codec poc_codec_t;

struct poc_codec {
    /* Encode one frame of PCM → compressed bytes.
     * Returns number of bytes written, or < 0 on error. */
    int  (*encode)(poc_codec_t *c, const int16_t *pcm, int n_samples,
                   uint8_t *out, int out_max);

    /* Decode compressed bytes → one frame of PCM.
     * If `in` is NULL or in_len is 0, runs Opus PLC for a missing frame.
     * Returns number of samples written, or < 0 on error. */
    int  (*decode)(poc_codec_t *c, const uint8_t *in, int in_len,
                   int16_t *pcm, int pcm_max);

    /* Decode the FEC redundancy embedded in the *next* packet to
     * reconstruct the previously-lost frame. `in` MUST be the next
     * received packet (sequence N+1) when frame N is missing. */
    int  (*decode_fec)(poc_codec_t *c, const uint8_t *in, int in_len,
                       int16_t *pcm, int pcm_max);

    void (*destroy)(poc_codec_t *c);

    int  sample_rate;       /* always 24000 */
    int  frame_samples;     /* always 480 */
    int  frame_ms;          /* always 20 */
    int  max_encoded_size;  /* always POC_CODEC_MAX_ENCODED_SIZE */
};

/* Create the Opus SWB codec. Returns NULL on allocation failure. */
poc_codec_t *poc_codec_create(void);

static inline void poc_codec_destroy(poc_codec_t *c)
{
    if (c && c->destroy)
        c->destroy(c);
}

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

static inline int poc_codec_decode_fec(poc_codec_t *c, const uint8_t *in,
                                       int in_len, int16_t *pcm, int pcm_max)
{
    return c->decode_fec(c, in, in_len, pcm, pcm_max);
}

#endif /* POC_CODEC_H */
