/*
 * test_fec.c — Tests for audio forward error correction
 */

#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_fec(void)
{
    poc_fec_t fec;

    {
        test_begin("fec: init with default group size");
        poc_fec_init(&fec, 0);
        test_assert(fec.group_size == POC_FEC_DEFAULT_GROUP, "default=3");
    }

    {
        test_begin("fec: init with custom group size");
        poc_fec_init(&fec, 4);
        test_assert(fec.group_size == 4, "should be 4");
    }

    /* Encoder: 3 data frames produce 1 parity at end */
    {
        test_begin("fec: encoder produces parity after group_size frames");
        poc_fec_init(&fec, 3);
        fec.enabled = true;

        uint8_t frame1[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        uint8_t frame2[20] = {20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
        uint8_t frame3[20] = {0};
        memset(frame3, 0x55, 20);

        uint8_t out1[64], out2[64];

        int n1 = poc_fec_encode(&fec, frame1, 20, out1, out2, 64);
        test_assert(n1 == 1, "first frame: data only");
    }

    {
        test_begin("fec: third frame produces data + parity");
        poc_fec_init(&fec, 3);
        fec.enabled = true;

        uint8_t f1[20], f2[20], f3[20];
        memset(f1, 0xAA, 20);
        memset(f2, 0xBB, 20);
        memset(f3, 0xCC, 20);

        uint8_t out1[64], out2[64];
        poc_fec_encode(&fec, f1, 20, out1, out2, 64);
        poc_fec_encode(&fec, f2, 20, out1, out2, 64);
        int n3 = poc_fec_encode(&fec, f3, 20, out1, out2, 64);
        test_assert(n3 == 2, "third frame should emit parity");
    }

    /* Parity is XOR of all frames */
    {
        test_begin("fec: parity is XOR of data frames");
        poc_fec_init(&fec, 3);
        fec.enabled = true;

        uint8_t f1[4] = {0xFF, 0x00, 0xAA, 0x55};
        uint8_t f2[4] = {0x00, 0xFF, 0x55, 0xAA};
        uint8_t f3[4] = {0x11, 0x22, 0x33, 0x44};

        uint8_t out1[64], parity[64];
        poc_fec_encode(&fec, f1, 4, out1, parity, 64);
        poc_fec_encode(&fec, f2, 4, out1, parity, 64);
        poc_fec_encode(&fec, f3, 4, out1, parity, 64);

        /* parity should be f1 XOR f2 XOR f3 */
        uint8_t expected[4];
        for (int i = 0; i < 4; i++)
            expected[i] = f1[i] ^ f2[i] ^ f3[i];
        test_assert(memcmp(parity, expected, 4) == 0, "parity=XOR of all");
    }

    /* Decoder: can reconstruct one missing frame */
    {
        test_begin("fec: decoder reconstructs missing frame");
        poc_fec_init(&fec, 3);
        fec.enabled = true;

        uint8_t f1[4] = {0x10, 0x20, 0x30, 0x40};
        uint8_t f2[4] = {0x50, 0x60, 0x70, 0x80};
        uint8_t f3[4] = {0x90, 0xA0, 0xB0, 0xC0};
        uint8_t parity_data[4];
        for (int i = 0; i < 4; i++)
            parity_data[i] = f1[i] ^ f2[i] ^ f3[i];

        uint8_t out[64];
        /* Feed frame 0 and frame 2 (skip frame 1) */
        poc_fec_decode(&fec, f1, 4, 0, out, 64);
        poc_fec_decode(&fec, f3, 4, 2, out, 64);
        /* Feed parity — should reconstruct frame 1 */
        int rlen = poc_fec_decode(&fec, parity_data, 4, 3, out, 64);

        test_assert(rlen == 4 && memcmp(out, f2, 4) == 0,
                    "should reconstruct f2");
    }

    /* Destroy is safe */
    {
        test_begin("fec: destroy is safe");
        poc_fec_destroy(&fec);
        test_assert(fec.group_size == 0, "zeroed");
    }
}
