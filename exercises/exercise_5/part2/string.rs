
/**
 * In C, C++ and Rust write a function that takes a string as input, and returns a new
string equal to the input but where &, <and >is replaced respectively with &amp;,
&lt;and &gt;
¥Write examples with outputs where you use this function in the main() functions in
the various programming languages
 */

use std::io::{self, Write};

fn escape_html(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}

fn main() {
        print!("Enter a string: ");
        io::stdout().flush().unwrap(); 
        
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let input = input.trim(); 
                
                println!("Original: {}", input);
                println!("Escaped:  {}", escape_html(input));
                println!();
            }
            Err(error) => {
                println!("Error reading input: {}", error);
                return;
            }
        }
}
