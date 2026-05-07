/*
 * test_main.c — Test harness for libpoc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_total;
static int g_passed;
static int g_failed;
static int g_in_test;

void test_begin(const char *name)
{
    int extra = 0;
    for (const char *p = name; *p; p++)
        if ((*p & 0xC0) == 0x80) extra++;
    printf("  %-*s ", 50 + extra, name);
    g_total++;
    g_in_test = 1;
}

void test_pass(void)
{
    if (!g_in_test) return;
    printf("PASS\n");
    g_passed++;
    g_in_test = 0;
}

void test_fail(const char *msg)
{
    if (!g_in_test) return;
    printf("FAIL: %s\n", msg);
    g_failed++;
    g_in_test = 0;
}

void test_assert(int cond, const char *msg)
{
    if (cond)
        test_pass();
    else
        test_fail(msg);
}

void test_end(void)
{
    if (g_in_test)
        test_pass();
}

extern void test_util(void);
extern void test_crypto(void);
extern void test_tcp_frame(void);
extern void test_msg_build(void);
extern void test_msg_parse(void);
extern void test_codec(void);
extern void test_encrypt(void);
extern void test_gps(void);
extern void test_jitter(void);
extern void test_ring(void);

int main(void)
{
    printf("libpoc test suite\n");
    printf("==================\n\n");

    printf("Utility functions:\n");
    test_util();

    printf("\nCrypto (SHA1, HMAC-SHA1):\n");
    test_crypto();

    printf("\nTCP MS-frame framing:\n");
    test_tcp_frame();

    printf("\nMessage builders:\n");
    test_msg_build();

    printf("\nMessage parser dispatch:\n");
    test_msg_parse();

    printf("\nAudio codec (Opus SWB):\n");
    test_codec();

    printf("\nEncryption (AES):\n");
    test_encrypt();

    printf("\nGPS reporting:\n");
    test_gps();

    printf("\nJitter buffer (Opus FEC + reorder):\n");
    test_jitter();

    printf("\nRing buffer & event queue:\n");
    test_ring();

    printf("\n==================\n");
    printf("Results: %d/%d passed", g_passed, g_total);
    if (g_failed > 0)
        printf(", %d FAILED", g_failed);
    printf("\n");

    return g_failed > 0 ? 1 : 0;
}
