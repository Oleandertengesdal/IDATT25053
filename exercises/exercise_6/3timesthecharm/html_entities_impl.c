#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Replaces HTML special characters with their entity equivalents
 * & -> &amp;
 * < -> &lt;
 * > -> &gt;
 */
char* replace_html_entities(const char* input) {
    //if (!input) return NULL;  // Add NULL check
    
    size_t len = strlen(input);
    size_t new_len = len;
    
    // Calculate new length
    for (size_t i = 0; i < len; i++) {
        if (input[i] == '&') new_len += 4; // &amp; (5 chars total, 1 already counted)
        else if (input[i] == '<') new_len += 3; // &lt; (4 chars total)
        else if (input[i] == '>') new_len += 3; // &gt; (4 chars total)
    }
    
    char* output = malloc(new_len + 1);
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

int main() {
    char input[256];
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline character
    
    char *output = replace_html_entities(input);
    if (output) {
        printf("Output: %s\n", output);
        free(output);
    } else {
        printf("Error: Memory allocation failed\n");
    }
    return 0;
}