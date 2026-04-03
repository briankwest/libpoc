/*
 * test_codec_wav.c — Encode/decode WAV files through Speex codec
 *
 * Reads 8kHz 16-bit mono WAV files from tests/wav/, roundtrips them
 * through Speex, writes output to tests/wav/speex/.
 *
 * Usage: test_codec_wav [input_dir]
 */

#include "poc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct { int16_t *samples; int n_samples; int sample_rate; } wav_data_t;

static int wav_read(const char *path, wav_data_t *wav)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t hdr[44];
    if (fread(hdr, 1, 44, f) != 44) { fclose(f); return -1; }
    if (memcmp(hdr, "RIFF", 4) || memcmp(hdr + 8, "WAVE", 4)) { fclose(f); return -1; }
    if (*(int16_t *)(hdr + 20) != 1 || *(int16_t *)(hdr + 22) != 1 || *(int16_t *)(hdr + 34) != 16)
        { fclose(f); return -1; }
    wav->sample_rate = *(int32_t *)(hdr + 24);
    int32_t data_size = *(int32_t *)(hdr + 40);
    wav->samples = malloc(data_size);
    if (!wav->samples) { fclose(f); return -1; }
    int rd = fread(wav->samples, 1, data_size, f);
    fclose(f);
    wav->n_samples = rd / 2;
    return 0;
}

static int wav_write(const char *path, const int16_t *samples, int n, int rate)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int32_t ds = n * 2, fs = 36 + ds;
    uint8_t h[44] = {0};
    memcpy(h, "RIFF", 4); *(int32_t*)(h+4) = fs;
    memcpy(h+8, "WAVEfmt ", 8); *(int32_t*)(h+16) = 16;
    *(int16_t*)(h+20) = 1; *(int16_t*)(h+22) = 1;
    *(int32_t*)(h+24) = rate; *(int32_t*)(h+28) = rate*2;
    *(int16_t*)(h+32) = 2; *(int16_t*)(h+34) = 16;
    memcpy(h+36, "data", 4); *(int32_t*)(h+40) = ds;
    fwrite(h, 1, 44, f); fwrite(samples, 2, n, f); fclose(f);
    return 0;
}

static int resample(const int16_t *in, int in_len, int in_rate, int16_t **out, int out_rate)
{
    int out_len = (int)((int64_t)in_len * out_rate / in_rate);
    if (out_len <= 0) { *out = NULL; return 0; }
    *out = malloc(out_len * sizeof(int16_t));
    if (!*out) return 0;
    for (int i = 0; i < out_len; i++) {
        double pos = (double)i * in_rate / out_rate;
        int idx = (int)pos; double frac = pos - idx;
        (*out)[i] = (idx + 1 < in_len)
            ? (int16_t)((1.0 - frac) * in[idx] + frac * in[idx + 1])
            : (idx < in_len) ? in[idx] : 0;
    }
    return out_len;
}

int main(int argc, char **argv)
{
    const char *input_dir = (argc > 1) ? argv[1] : "tests/wav";
    char speex_dir[1024];
    snprintf(speex_dir, sizeof(speex_dir), "%s/speex", input_dir);
    mkdir(speex_dir, 0755);

    DIR *dir = opendir(input_dir);
    if (!dir) { fprintf(stderr, "Cannot open %s\n", input_dir); return 1; }

    int total = 0, ok = 0;
    struct dirent *ent;

    printf("Speex codec roundtrip test\n");
    printf("==========================\n");
    printf("Input:  %s\nOutput: %s\n\n", input_dir, speex_dir);

    while ((ent = readdir(dir)) != NULL) {
        int len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 4, ".wav") != 0) continue;

        char inpath[1024];
        snprintf(inpath, sizeof(inpath), "%s/%s", input_dir, ent->d_name);
        wav_data_t wav;
        if (wav_read(inpath, &wav) < 0) continue;
        total++;

        printf("%-40s  %5.1fs  %dHz", ent->d_name,
               (double)wav.n_samples / wav.sample_rate, wav.sample_rate);

        int16_t *pcm8k = wav.samples;
        int n8k = wav.n_samples;
        int need_free = 0;
        if (wav.sample_rate != 8000) {
            n8k = resample(wav.samples, wav.n_samples, wav.sample_rate, &pcm8k, 8000);
            need_free = 1;
        }

        int frames = (n8k / POC_AUDIO_FRAME_SAMPLES) * POC_AUDIO_FRAME_SAMPLES;
        if (frames == 0) { printf("  (too short)\n"); free(wav.samples); if (need_free) free(pcm8k); continue; }

        poc_speex_t spx;
        poc_speex_init(&spx);
        int16_t *out = calloc(frames, sizeof(int16_t));
        int out_n = 0;
        for (int f = 0; f < frames / POC_AUDIO_FRAME_SAMPLES; f++) {
            uint8_t enc[SPEEX_FRAME_ENC];
            int el = poc_speex_encode(&spx, pcm8k + f * POC_AUDIO_FRAME_SAMPLES, enc);
            if (el > 0) {
                int dl = poc_speex_decode(&spx, enc, el, out + f * POC_AUDIO_FRAME_SAMPLES);
                if (dl > 0) out_n += dl;
            }
        }
        poc_speex_destroy(&spx);

        char outpath[1024];
        snprintf(outpath, sizeof(outpath), "%s/%s", speex_dir, ent->d_name);
        if (out_n > 0 && wav_write(outpath, out, out_n, 8000) == 0) {
            printf("  OK\n"); ok++;
        } else {
            printf("  FAIL\n");
        }
        free(out); free(wav.samples); if (need_free) free(pcm8k);
    }
    closedir(dir);

    printf("\n==========================\n");
    printf("Files: %d  Passed: %d/%d\n", total, ok, total);
    return (ok == total) ? 0 : 1;
}
