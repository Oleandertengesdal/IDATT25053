#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// your header that declares: char *replace_html_entities(const char *s);
#include "strings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const size_t MAX_INPUT = 1 << 20; // 1 MB
    if (size == 0 || size > MAX_INPUT) return 0;

    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    char *output = replace_html_entities(input);

    if (output) free(output);
    free(input);

    return 0;
}