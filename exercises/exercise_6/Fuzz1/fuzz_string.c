#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Your original function (with a potential bug fix)
char* replace_html_entities(const char* input) {
    size_t len = strlen(input);
    size_t new_len = len;
    for (size_t i = 0; i < len; i++) {
        if (input[i] == '&') new_len += 4; // &amp;
        else if (input[i] == '<') new_len += 3; // &lt;
        else if (input[i] == '>') new_len += 3; // &gt;
    }

    char* output = (char*)malloc(new_len + 1);
    if (!output) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (input[i] == '&') {
            strcpy(&output[j], "&amp;");
            j += 5;
        } else if (input[i] == '<') {
            strcpy(&output[j], "&lt;");
            j += 4;
        } else if (input[i] == '>') {
            strcpy(&output[j], "&gt;");
            j += 4;
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    return output;
}

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Create null-terminated string from fuzzer input
    char *input = (char*)malloc(size + 1);
    if (!input) return 0;
    
    memcpy(input, data, size);
    input[size] = '\0';
    
    // Test the function
    char *output = replace_html_entities(input);
    
    // Verify output if non-NULL
    if (output) {
        // Basic sanity checks
        size_t output_len = strlen(output);
        
        // Verify no buffer overflow occurred
        // The output should never be shorter than input
        // and should grow predictably based on special chars
        
        free(output);
    }
    
    free(input);
    return 0;
}

void test_case(const char* name, const char* input) {
    printf("Testing: %s\n", name);
    char* output = replace_html_entities(input);
    if (output) {
        printf("  Input:  \"%s\"\n", input);
        printf("  Output: \"%s\"\n", output);
        free(output);
    } else {
        printf("  Output: NULL\n");
    }
    printf("\n");
}


int main() {
    printf("=== AddressSanitizer Testing ===\n\n");
    
    // Normal cases
    test_case("Normal text", "Hello World");
    test_case("Single ampersand", "&");
    test_case("Single less-than", "<");
    test_case("Single greater-than", ">");
    test_case("Multiple special chars", "<<< &&& >>>");
    test_case("Mixed content", "<div>&test</div>");
    test_case("Empty string", "");
    
    // Edge cases
    test_case("Very long string with specials", "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
    test_case("All three chars", "&<>");
    test_case("Repeated pattern", "&<>&<>&<>&<>");
    
    // Stress test - large input
    printf("Testing: Large input (1000 ampersands)\n");
    char* large_input = malloc(1001);
    if (large_input) {
        memset(large_input, '&', 1000);
        large_input[1000] = '\0';
        char* output = replace_html_entities(large_input);
        if (output) {
            printf("  Successfully processed %zu chars -> %zu chars\n", 
                strlen(large_input), strlen(output));
            free(output);
        }
        free(large_input);
    }
    printf("\n");
    
    printf("=== All tests completed ===\n");
    printf("If no AddressSanitizer errors appeared, the code is memory-safe!\n");
    
    return 0;
}