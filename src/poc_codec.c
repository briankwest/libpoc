/*
 * poc_codec.c — Opus super-wideband codec
 *
 * Hardcoded profile: 24 kHz mono, 20 ms frames (480 samples), 32 kbps
 * VBR, inband FEC at 10 % packet-loss target, complexity 10, VOIP app.
 * The matching parameters are mirrored in reflectd's link_probe (see
 * include/kerchunk_link_proto.h) so audio quality matches across
 * the kerchunk bridge and the iOS PT-framework client.
 */

#include "poc_internal.h"
#include <opus/opus.h>
#include <stdlib.h>

/* Hardcoded Opus profile constants. Edit here if the audio profile
 * needs to change; everything else picks up the new values via
 * poc_codec.h. */
#define POC_OPUS_SAMPLE_RATE  24000
#define POC_OPUS_FRAME_MS     20
#define POC_OPUS_FRAME_SAMPLES (POC_OPUS_SAMPLE_RATE * POC_OPUS_FRAME_MS / 1000)
#define POC_OPUS_BITRATE      32000
#define POC_OPUS_LOSS_PCT     10
#define POC_OPUS_COMPLEXITY   10

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
    /* in == NULL means "frame lost" — Opus runs PLC. */
    int samples = opus_decode(o->dec, in, in_len, pcm, pcm_max, 0);
    return samples > 0 ? samples : -1;
}

static int opus_dec_fec(poc_codec_t *c, const uint8_t *in, int in_len,
                        int16_t *pcm, int pcm_max)
{
    poc_opus_codec_t *o = (poc_opus_codec_t *)c;
    /* `in` is the packet AFTER the missing one — its LBRR redundancy
     * carries a low-bitrate copy of the missing frame. */
    int samples = opus_decode(o->dec, in, in_len, pcm, pcm_max, 1);
    return samples > 0 ? samples : -1;
}

static void opus_destroy_fn(poc_codec_t *c)
{
    poc_opus_codec_t *o = (poc_opus_codec_t *)c;
    if (o->enc) opus_encoder_destroy(o->enc);
    if (o->dec) opus_decoder_destroy(o->dec);
    free(o);
}

poc_codec_t *poc_codec_create(void)
{
    poc_opus_codec_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;

    int err;
    o->enc = opus_encoder_create(POC_OPUS_SAMPLE_RATE, 1,
                                 OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !o->enc) { free(o); return NULL; }

    o->dec = opus_decoder_create(POC_OPUS_SAMPLE_RATE, 1, &err);
    if (err != OPUS_OK || !o->dec) {
        opus_encoder_destroy(o->enc);
        free(o);
        return NULL;
    }

    opus_encoder_ctl(o->enc, OPUS_SET_BITRATE(POC_OPUS_BITRATE));
    opus_encoder_ctl(o->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(o->enc, OPUS_SET_PACKET_LOSS_PERC(POC_OPUS_LOSS_PCT));
    opus_encoder_ctl(o->enc, OPUS_SET_COMPLEXITY(POC_OPUS_COMPLEXITY));

    o->base.encode = opus_enc;
    o->base.decode = opus_dec;
    o->base.decode_fec = opus_dec_fec;
    o->base.destroy = opus_destroy_fn;
    o->base.sample_rate = POC_OPUS_SAMPLE_RATE;
    o->base.frame_samples = POC_OPUS_FRAME_SAMPLES;
    o->base.frame_ms = POC_OPUS_FRAME_MS;
    o->base.max_encoded_size = POC_CODEC_MAX_ENCODED_SIZE;

    poc_log("codec: opus SWB %d Hz, %d-sample frames, %d bps, FEC=%d%%",
            POC_OPUS_SAMPLE_RATE, POC_OPUS_FRAME_SAMPLES,
            POC_OPUS_BITRATE, POC_OPUS_LOSS_PCT);
    return &o->base;
}
