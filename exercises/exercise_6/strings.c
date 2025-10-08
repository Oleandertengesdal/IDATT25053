#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * In C, C++ and Rust write a function that takes a string as input, and returns a new
string equal to the input but where &, <and >is replaced respectively with &amp;,
&lt;and &gt;
¥Write examples with outputs where you use this function in the main() functions in
the various programming languages
 */

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

int main() {
    char input[256];
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline character

    char *output = replace_html_entities(input);
    printf("Output: %s\n", output);
    free(output);
    return 0;
}