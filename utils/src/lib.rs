extern crate proc_macro;
use proc_macro::TokenStream;

// The input string should be a space-separated list of hex values without '0x'.
// For example, hex!("81 a5 9f bc 02").
#[proc_macro]
pub fn hex(input: TokenStream) -> TokenStream {
    let mut s = String::new();
    s.push('[');

    // Parse the input values and prepend '0x' to each.
    let mut iter = input.into_iter();
    match iter.next() {
        Some(hex_string) => {
            let mut is_first_word = true;
            let mut finished_current_number = true;

            for ch in hex_string.to_string().chars() {
                match ch {
                    // '"' => (),
                    '0'..='9' | 'a'..='f' | 'A'..='F' => {
                        if finished_current_number {
                            if !is_first_word {
                                s.push_str(", ");
                            }
                            s.push_str("0x");

                            is_first_word = false;
                            finished_current_number = false;
                        }

                        s.push(ch);
                    },
                    _ => {
                        finished_current_number = true;
                    }
                }
            }
        },
        None => panic!("Missing expression"),
    };

    s.push(']');
    s.parse().unwrap()
}