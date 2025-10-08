// fuzz_afl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "strings.h"

int main(int argc, char **argv) {
    // Read input file (AFL calls ./target @@)
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    rewind(f);

    // optional cap
    if (sz == 0 || sz > (1 << 20)) { fclose(f); return 0; } // 1 MiB cap

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return 1; }

    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return 1; }
    buf[sz] = '\0';
    fclose(f);

    char *out = replace_html_entities(buf);

    if (out) free(out);
    free(buf);
    return 0;
}
