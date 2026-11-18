#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "json_object.h"
#include "json_tokener.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }

    char *data = (char *)malloc((size_t)len + 1);
    if (!data) {
        fclose(f);
        return 1;
    }

    size_t read_len = fread(data, 1, (size_t)len, f);
    data[read_len] = '\0';
    fclose(f);

    if (read_len > (size_t)INT_MAX) {
        fprintf(stderr, "Input file too large\n");
        free(data);
        return 1;
    }

    json_tokener *tok = json_tokener_new();
    if (!tok) {
        fprintf(stderr, "Failed to allocate json_tokener\n");
        free(data);
        return 1;
    }

    /* Enforce RFC 8259 strict parsing and reject trailing non-whitespace characters */
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

    struct json_object *obj = json_tokener_parse_ex(tok, data, (int)read_len);
    enum json_tokener_error jerr = json_tokener_get_error(tok);
    size_t consumed = json_tokener_get_parse_end(tok);

    /* Signal EOF if the tokener is waiting for a delimiter (e.g., standalone `true` or `123`) */
    if (obj == NULL && jerr == json_tokener_continue) {
        obj = json_tokener_parse_ex(tok, "", 1);
        jerr = json_tokener_get_error(tok);
    }

    if (!obj || jerr != json_tokener_success || consumed != read_len) {
        fprintf(stderr, "Parse error: %s\n", json_tokener_error_desc(jerr));
        if (obj) {
            json_object_put(obj);
        }
        json_tokener_free(tok);
        free(data);
        return 1;
    }

    /* Print clean normalized JSON output to stdout */
    const char *out = json_object_to_json_string_ext(
        obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE
    );
    if (out) {
        printf("%s\n", out);
    }

    json_object_put(obj);
    json_tokener_free(tok);
    free(data);
    return 0;
}