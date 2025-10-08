#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration of the function to fuzz
char* replace_html_entities(const char* input);

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have a null-terminated string
    if (size == 0) return 0;
    
    // Create a null-terminated copy of the input
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    
    memcpy(input, data, size);
    input[size] = '\0';
    
    // Call the function under test
    char *output = replace_html_entities(input);
    
    // Clean up
    if (output) {
        free(output);
    }
    free(input);
    
    return 0;
}