/**
 * In C, C++ and Rust write a function that takes a string as input, and returns a new
string equal to the input but where &, <and >is replaced respectively with &amp;,
&lt;and &gt;
¥Write examples with outputs where you use this function in the main() functions in
the various programming languages
 */
#include <iostream>
#include <string>
#include <sstream>

int main() {
    std::string input;
    std::cout << "Enter a string: ";
    std::getline(std::cin, input);

    std::ostringstream output;
    for (char c : input) {
        if (c == '&') {
            output << "&amp;";
        } else if (c == '<') {
            output << "&lt;";
        } else if (c == '>') {
            output << "&gt;";
        } else {
            output << c;
        }
    }

    std::cout << "Output: " << output.str() << std::endl;
    return 0;
}