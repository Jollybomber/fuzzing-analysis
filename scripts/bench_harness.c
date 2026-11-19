/*
 * In-process overhead benchmark harness.
 *
 * Loads every input listed in a file into memory once, then parses and
 * serializes each input `loops` times, exactly as the wrappers
 * (cjson_parse.c / jsonc_parse.c) do, and reports the elapsed time.
 * Process start-up and file I/O are excluded, so the measurement isolates
 * the parser work that sanitizer instrumentation slows down.
 *
 * Build with -DBENCH_CJSON or -DBENCH_JSONC (see scripts/benchmark_overhead.py).
 * Usage: bench <input_list_file> <loops>
 * Output (one line): ns=<total> inputs=<n> loops=<k> accepted=<per pass> sink=<bytes>
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(BENCH_CJSON)
#include "cJSON.h"
#elif defined(BENCH_JSONC)
#include "json_object.h"
#include "json_tokener.h"
#else
#error "Define BENCH_CJSON or BENCH_JSONC"
#endif

typedef struct {
    char *data;
    size_t len;
} input_t;

static size_t sink; /* Prevents the compiler from discarding serialization work. */

#if defined(BENCH_CJSON)
static int parse_one(const char *data, size_t len) {
    const char *end = NULL;
    cJSON *json = cJSON_ParseWithLengthOpts(data, len + 1, &end, 1);
    int ok = json != NULL && end == data + len;
    if (ok) {
        char *out = cJSON_PrintUnformatted(json);
        if (out) {
            sink += strlen(out);
            free(out);
        }
    }
    if (json) cJSON_Delete(json);
    return ok;
}
#else
static int parse_one(const char *data, size_t len) {
    if (len > (size_t)INT_MAX) return 0;
    json_tokener *tok = json_tokener_new();
    if (!tok) return 0;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    struct json_object *obj = json_tokener_parse_ex(tok, data, (int)len);
    enum json_tokener_error err = json_tokener_get_error(tok);
    size_t consumed = json_tokener_get_parse_end(tok);
    if (obj == NULL && err == json_tokener_continue) {
        obj = json_tokener_parse_ex(tok, "", 1);
        err = json_tokener_get_error(tok);
    }
    int ok = err == json_tokener_success && consumed == len;
    if (ok) {
        const char *out = obj ? json_object_to_json_string_ext(
                                    obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE)
                              : "null";
        if (out) sink += strlen(out);
    }
    if (obj) json_object_put(obj);
    json_tokener_free(tok);
    return ok;
}
#endif

static int load(const char *path, input_t *in) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long len = ftell(f);
    if (len < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    in->data = malloc((size_t)len + 1);
    if (!in->data) { fclose(f); return -1; }
    in->len = fread(in->data, 1, (size_t)len, f);
    in->data[in->len] = '\0';
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_list_file> <loops>\n", argv[0]);
        return 2;
    }
    long loops = strtol(argv[2], NULL, 10);
    if (loops < 1) { fprintf(stderr, "loops must be >= 1\n"); return 2; }

    FILE *list = fopen(argv[1], "r");
    if (!list) { perror("input list"); return 2; }
    size_t cap = 1024, n = 0;
    input_t *inputs = malloc(cap * sizeof *inputs);
    char line[8192];
    while (inputs && fgets(line, sizeof line, list)) {
        line[strcspn(line, "\n")] = '\0';
        if (!line[0]) continue;
        if (n == cap) {
            cap *= 2;
            input_t *grown = realloc(inputs, cap * sizeof *inputs);
            if (!grown) { free(inputs); inputs = NULL; break; }
            inputs = grown;
        }
        if (load(line, &inputs[n]) != 0) { fprintf(stderr, "Cannot read %s\n", line); return 2; }
        n++;
    }
    fclose(list);
    if (!inputs || n == 0) { fprintf(stderr, "No inputs loaded\n"); return 2; }

    size_t accepted = 0;
    for (size_t i = 0; i < n; i++) accepted += (size_t)parse_one(inputs[i].data, inputs[i].len); /* warm-up */

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long k = 0; k < loops; k++)
        for (size_t i = 0; i < n; i++) parse_one(inputs[i].data, inputs[i].len);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    unsigned long long ns = (unsigned long long)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                          + (unsigned long long)(t1.tv_nsec - t0.tv_nsec);
    printf("ns=%llu inputs=%zu loops=%ld accepted=%zu sink=%zu\n", ns, n, loops, accepted, sink);
    for (size_t i = 0; i < n; i++) free(inputs[i].data);
    free(inputs);
    return 0;
}
