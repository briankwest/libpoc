/*
 * poc_fec.c — Audio Forward Error Correction
 *
 * Simple XOR-based FEC for audio frames. The FEC scheme sends
 * N data frames followed by
 * 1 parity frame (XOR of the preceding N frames). On loss, the
 * missing frame can be reconstructed from the parity + remaining frames.
 *
 * FEC group size: typically 3 data + 1 parity (configurable).
 */

#include "poc_internal.h"
#include <string.h>

void poc_fec_init(poc_fec_t *fec, int group_size)
{
    memset(fec, 0, sizeof(*fec));
    fec->group_size = (group_size > 0 && group_size <= POC_FEC_MAX_GROUP)
                      ? group_size : POC_FEC_DEFAULT_GROUP;
    fec->enabled = false;
}

void poc_fec_destroy(poc_fec_t *fec)
{
    memset(fec, 0, sizeof(*fec));
}

/*
 * Encoder: feed one encoded audio frame, get back the frame to send.
 * After every group_size frames, also outputs a parity frame.
 *
 * Returns: number of output frames (1 = data only, 2 = data + parity)
 * out1 = the data frame (copy of in), out2 = parity frame (if 2 returned)
 */
int poc_fec_encode(poc_fec_t *fec, const uint8_t *in, int in_len,
                   uint8_t *out1, uint8_t *out2, int out_max)
{
    if (in_len > out_max || in_len > POC_FEC_MAX_FRAME)
        return 0;

    /* Copy through the data frame */
    memcpy(out1, in, in_len);

    /* Accumulate parity (XOR) */
    if (fec->enc_count == 0) {
        memcpy(fec->parity, in, in_len);
        fec->parity_len = in_len;
    } else {
        int plen = in_len < fec->parity_len ? in_len : fec->parity_len;
        for (int i = 0; i < plen; i++)
            fec->parity[i] ^= in[i];
    }

    fec->enc_count++;

    if (fec->enc_count >= fec->group_size) {
        /* Output parity frame */
        memcpy(out2, fec->parity, fec->parity_len);
        fec->enc_count = 0;
        return 2;
    }

    return 1;
}

/*
 * Decoder: feed received frames (data or parity).
 * seq_in_group: position in FEC group (0..group_size-1 for data, group_size for parity)
 * Returns the decoded frame in `out`, or reconstructs a missing frame.
 *
 * For simplicity, this just passes through — reconstruction requires
 * tracking which frames in the group were received, which we add later
 * if dropout testing shows it's needed.
 */
int poc_fec_decode(poc_fec_t *fec, const uint8_t *in, int in_len,
                   int seq_in_group, uint8_t *out, int out_max)
{
    if (in_len > out_max || in_len > POC_FEC_MAX_FRAME)
        return 0;
    if (seq_in_group < 0 || seq_in_group > fec->group_size)
        return 0;

    /* Store frame in decode window */
    if (seq_in_group < fec->group_size) {
        memcpy(fec->dec_frames[seq_in_group], in, in_len);
        fec->dec_frame_len[seq_in_group] = in_len;
        fec->dec_received |= (1 << seq_in_group);
    } else {
        /* This is the parity frame */
        memcpy(fec->dec_parity, in, in_len);
        fec->dec_parity_len = in_len;
        fec->dec_has_parity = true;
    }

    /* Pass through the data frame */
    memcpy(out, in, in_len);

    /* Check if we can reconstruct a missing frame */
    if (fec->dec_has_parity && seq_in_group == fec->group_size) {
        int missing = -1;
        int missing_count = 0;
        for (int i = 0; i < fec->group_size; i++) {
            if (!(fec->dec_received & (1 << i))) {
                missing = i;
                missing_count++;
            }
        }

        if (missing_count == 1 && missing >= 0) {
            /* Reconstruct: XOR parity with all received frames */
            int plen = fec->dec_parity_len;
            memcpy(out, fec->dec_parity, plen);
            for (int i = 0; i < fec->group_size; i++) {
                if (i == missing) continue;
                int flen = fec->dec_frame_len[i] < plen ? fec->dec_frame_len[i] : plen;
                for (int j = 0; j < flen; j++)
                    out[j] ^= fec->dec_frames[i][j];
            }
            poc_log("fec: reconstructed frame %d in group", missing);
            fec->dec_received = 0;
            fec->dec_has_parity = false;
            return plen;
        }

        /* Reset for next group */
        fec->dec_received = 0;
        fec->dec_has_parity = false;
    }

    return in_len;
}
