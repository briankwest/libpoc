/*
 * poc_codec.c — Speex narrowband codec wrapper
 *
 * Frame: 160 samples (20ms @ 8kHz) -> 20 bytes encoded (mode 4)
 */

#include "poc_internal.h"
#include <string.h>

int poc_speex_init(poc_speex_t *s)
{
    memset(s, 0, sizeof(*s));

    /* Narrowband encoder */
    s->enc_state = speex_encoder_init(&speex_nb_mode);
    if (!s->enc_state)
        return POC_ERR;

    int quality = 4;
    speex_encoder_ctl(s->enc_state, SPEEX_SET_QUALITY, &quality);
    speex_encoder_ctl(s->enc_state, SPEEX_GET_FRAME_SIZE, &s->frame_size);
    speex_bits_init(&s->enc_bits);

    /* Narrowband decoder */
    s->dec_state = speex_decoder_init(&speex_nb_mode);
    if (!s->dec_state) {
        speex_encoder_destroy(s->enc_state);
        return POC_ERR;
    }
    speex_bits_init(&s->dec_bits);

    poc_log("speex: init ok, frame_size=%d", s->frame_size);
    return POC_OK;
}

void poc_speex_destroy(poc_speex_t *s)
{
    if (s->enc_state) {
        speex_encoder_destroy(s->enc_state);
        speex_bits_destroy(&s->enc_bits);
    }
    if (s->dec_state) {
        speex_decoder_destroy(s->dec_state);
        speex_bits_destroy(&s->dec_bits);
    }
    memset(s, 0, sizeof(*s));
}

/*
 * Encode one frame: 160 int16 samples -> encoded bytes
 * Returns number of bytes written to `out`, or < 0 on error.
 */
int poc_speex_encode(poc_speex_t *s, const int16_t *pcm, uint8_t *out)
{
    speex_bits_reset(&s->enc_bits);
    speex_encode_int(s->enc_state, (spx_int16_t *)pcm, &s->enc_bits);

    int nbytes = speex_bits_write(&s->enc_bits, (char *)out, SPEEX_FRAME_ENC);
    return nbytes;
}

/*
 * Decode one frame: encoded bytes -> 160 int16 samples
 * Returns number of samples decoded, or < 0 on error.
 */
int poc_speex_decode(poc_speex_t *s, const uint8_t *in, int in_len, int16_t *pcm)
{
    speex_bits_read_from(&s->dec_bits, (const char *)in, in_len);

    int rc = speex_decode_int(s->dec_state, &s->dec_bits, (spx_int16_t *)pcm);
    if (rc < 0)
        return rc;

    return s->frame_size;
}
