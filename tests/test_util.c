/*
 * test_util.c — Tests for byte order and utility functions
 */

#include "poc_internal.h"
#include <string.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_util(void)
{
    /* write16 / read16 */
    {
        test_begin("write16/read16 roundtrip");
        uint8_t buf[2];
        poc_write16(buf, 0x1234);
        test_assert(buf[0] == 0x12 && buf[1] == 0x34, "big-endian write");
    }
    {
        test_begin("read16 decodes big-endian");
        uint8_t buf[] = {0xAB, 0xCD};
        test_assert(poc_read16(buf) == 0xABCD, "expected 0xABCD");
    }

    /* write32 / read32 */
    {
        test_begin("write32/read32 roundtrip");
        uint8_t buf[4];
        poc_write32(buf, 0xDEADBEEF);
        test_assert(poc_read32(buf) == 0xDEADBEEF, "roundtrip");
    }
    {
        test_begin("write32 big-endian byte order");
        uint8_t buf[4];
        poc_write32(buf, 0x01020304);
        test_assert(buf[0] == 0x01 && buf[1] == 0x02 &&
                    buf[2] == 0x03 && buf[3] == 0x04, "byte order");
    }

    /* read16/read32 with zero */
    {
        test_begin("read16 zero");
        uint8_t buf[] = {0x00, 0x00};
        test_assert(poc_read16(buf) == 0, "expected 0");
    }
    {
        test_begin("read32 zero");
        uint8_t buf[] = {0x00, 0x00, 0x00, 0x00};
        test_assert(poc_read32(buf) == 0, "expected 0");
    }

    /* read16/read32 max */
    {
        test_begin("read16 0xFFFF");
        uint8_t buf[] = {0xFF, 0xFF};
        test_assert(poc_read16(buf) == 0xFFFF, "expected 0xFFFF");
    }
    {
        test_begin("read32 0xFFFFFFFF");
        uint8_t buf[] = {0xFF, 0xFF, 0xFF, 0xFF};
        test_assert(poc_read32(buf) == 0xFFFFFFFF, "expected 0xFFFFFFFF");
    }

    /* mono_ms returns nonzero */
    {
        test_begin("mono_ms returns nonzero");
        test_assert(poc_mono_ms() > 0, "should be > 0");
    }

    /* mono_ms is monotonic */
    {
        test_begin("mono_ms is monotonic");
        uint64_t a = poc_mono_ms();
        uint64_t b = poc_mono_ms();
        test_assert(b >= a, "b >= a");
    }
}
