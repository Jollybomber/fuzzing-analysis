#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

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

    /* Parse and require the entire input (up to trailing whitespace) to be consumed */
    const char *parse_end = NULL;
    cJSON *json = cJSON_ParseWithLengthOpts(data, read_len + 1, &parse_end, 1);
    if (!json || parse_end != data + read_len) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Parse error before: %s\n", error_ptr);
        } else {
            fprintf(stderr, "Parse error: trailing or incomplete input\n");
        }
        if (json) {
            cJSON_Delete(json);
        }
        free(data);
        return 1;
    }

    /* Print clean normalized JSON output to stdout */
    char *out = cJSON_PrintUnformatted(json);
    if (out) {
        printf("%s\n", out);
        free(out);
    }

    cJSON_Delete(json);
    free(data);
    return 0;
}