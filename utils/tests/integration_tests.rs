use utils;

#[test]
fn hex_macro_valid_input() {
    assert_eq!(utils::hex!("06 ba 7f 18"), [0x06, 0xba, 0x7f, 0x18]);
}

#[test]
fn hex_macro_multiline_input() {
    assert_eq!(utils::hex!("
        01 02 03
        b7 b8 b9"),
        [0x1, 0x2, 0x3, 0xb7, 0xb8, 0xb9]
    )
}

#[test]
fn hex_macro_upper_and_lower_case() {
    assert_eq!(utils::hex!("2a Fe D0 ab"), [0x2a, 0xfe, 0xd0, 0xab]);
}