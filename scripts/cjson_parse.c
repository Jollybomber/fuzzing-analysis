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

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len < 0) {
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

    /* Parse the JSON input */
    cJSON *json = cJSON_ParseWithLength(data, read_len);
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Parse error before: %s\n", error_ptr);
        } else {
            fprintf(stderr, "Parse error\n");
        }
        free(data);
        return 1;
    }

    /* Print normalized JSON output to stdout */
    char *out = cJSON_PrintUnformatted(json);
    if (out) {
        printf("%s\n", out);
        free(out);
    }

    cJSON_Delete(json);
    free(data);
    return 0;
}
