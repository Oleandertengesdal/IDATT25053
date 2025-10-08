#ifndef STRINGS_H
#define STRINGS_H

#include <stddef.h>

/**
 * Replaces HTML special characters with their entity equivalents
 * & -> &amp;
 * < -> &lt;
 * > -> &gt;
 * 
 * @param input The input string to escape
 * @return A newly allocated string with HTML entities, or NULL on error
 *         Caller must free the returned string
 */
char* replace_html_entities(const char* input);

#endif // STRINGS_H
