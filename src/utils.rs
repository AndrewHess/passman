macro_rules! random_array {
    ($type:ty, $len:expr) => {
        [0; $len]
            .iter()
            .map(|_| rand::random::<$type>())
            .collect::<Vec<$type>>()
            .try_into()
            .unwrap()
    };
}
pub(crate) use random_array;

macro_rules! secure_random_bytes {
    ($len:expr) => {{
        let mut arr = [0u8; $len];
        let mut csprng = rand::rngs::StdRng::from_entropy();
        csprng.fill_bytes(&mut arr);
        arr
    }};
}
pub(crate) use secure_random_bytes;

macro_rules! extract_all_bytes {
    ($arr:expr, $expected_len:expr) => {
        || -> Result<[u8; $expected_len], ()> {
            match $arr.len() {
                x if x == $expected_len => Ok($arr[..x].try_into().unwrap()),
                _ => Err(()),
            }
        }()
    };
}
pub(crate) use extract_all_bytes;

// Convert byte array into a hex String with no spaces.
// For example, [0x0a, 0xff, 0x30] -> "0aff30"
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold("".to_string(), |result: String, b: &u8| {
        result + &format!("{:02x}", *b)
    })
}

// Convert a hex String with no spaces into a byte Vector.
// For example, "0aff30" -> [0x0a, 0xff, 0x30]
pub fn hex_to_bytes(hex: &String) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let hex_as_bytes = hex.as_bytes();
    assert_eq!(hex_as_bytes.len() % 2, 0);

    let mut byte: u8 = 0x00;
    let mut is_high_nibble = 1;

    for hex_digit in hex_as_bytes {
        let mut nibble = match *hex_digit as char {
            '0'..='9' => *hex_digit - ('0' as u8),
            'a'..='f' => *hex_digit - ('a' as u8) + 10,
            'A'..='F' => *hex_digit - ('A' as u8) + 10,
            _ => panic!("unexpected char in hex_to_bytes: {}", hex_digit),
        };

        if is_high_nibble == 1 {
            nibble = nibble << 4;
        }

        byte |= nibble;

        if is_high_nibble == 0 {
            result.push(byte);
            byte = 0x00;
        }

        is_high_nibble += 1;
        is_high_nibble %= 2;
    }

    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn bytes_to_hex() {
        assert_eq!(
            super::bytes_to_hex(&[0x00, 0x4a, 0x02, 0x30, 0xff]),
            "004a0230ff"
        );
    }

    #[test]
    fn hex_to_bytes() {
        assert_eq!(
            super::hex_to_bytes(&"004a0230ff".to_string())[..],
            [0x00, 0x4a, 0x02, 0x30, 0xff]
        );
    }
}
