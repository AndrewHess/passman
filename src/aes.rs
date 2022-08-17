use utils;

// The following constants have their value because we're implementing
// the 256 version of AES.
const NUM_KEY_WORDS: usize = 8;  // Number of 32-bit words in the key (32 * 8 == 256).
const NUM_ROUNDS: usize = 14;

macro_rules! round_constant {
    ($round_div_num_key_words:expr) => (
        [0x01 << $round_div_num_key_words, 0x00, 0x00, 0x00]
    )
}

// The value at index `i` is for round `i * NUM_KEY_WORDS`.
const ROUND_CONSTANTS: [[u8; 4]; 8] = [
    round_constant!(0),  // This element is invalid and should never be used.
    round_constant!(0),
    round_constant!(1),
    round_constant!(2),
    round_constant!(3),
    round_constant!(4),
    round_constant!(5),
    round_constant!(6),
];

const STATE_ROWS: usize = 4;
const STATE_COLS: usize = 4;
type State = [[u8; STATE_COLS]; STATE_ROWS];

fn state_from_bytes(bytes: [u8; 16]) -> State {
    let mut state: State = [[0u8; 4]; 4];
    for i in 0..16 {
        state[i % 4][i / 4] = bytes[i];
    }

    state
}

fn state_to_bytes(state: State) -> [u8; 16] {
    transpose_state(state).iter().flatten().map(|x| *x).collect::<Vec<u8>>().try_into().unwrap()
}

fn transpose_state(state: State) -> State {
    // This requires that the type `State` is a square matrix.
    state.iter().enumerate()
        .map(|(row, arr)| arr.iter().enumerate().map(|(col, _)| state[col][row]).collect::<Vec<u8>>().try_into().unwrap())
        .collect::<Vec<[u8; 4]>>()
        .try_into()
        .unwrap()
}

const SUBSTITUTION_TABLE: [u8; 256] = utils::hex!("
    63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16"
);

const INVERSE_SUBSTITUTION_TABLE: [u8; 256] = utils::hex!("
    52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
    7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
    54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
    08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
    72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
    6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
    90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
    d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
    3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
    96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
    47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
    fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
    1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
    60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
    a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
    17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d"
);

const MIX_COLUMNS_MATRIX: [[u8; 4]; 4] = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
];

fn substitute_bytes(state: State) -> State {
    state.map(|arr| arr.map(|x| SUBSTITUTION_TABLE[x as usize]))
}

fn shift_rows(state: State) -> State {
    state.iter().enumerate().map(|(i, arr)| shift_array_left(arr, i))
        .collect::<Vec<[u8; 4]>>()
        .try_into()
        .unwrap()
}

fn shift_array_left(arr: &[u8; STATE_COLS], amount: usize) -> [u8; STATE_COLS] {
    arr.iter().enumerate().map(|(i, _)| arr[(i + amount) % STATE_ROWS])
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

fn shift_array_right(arr: &[u8; STATE_COLS], amount: usize) -> [u8; STATE_COLS] {
    assert!(amount < STATE_COLS);
    shift_array_left(arr, STATE_COLS - amount)
}

fn mix_columns(state: State) -> State {
    transpose_state(
        transpose_state(state).iter().map(|arr| rg_field_matrix_vector_mul(&MIX_COLUMNS_MATRIX, arr))
            .collect::<Vec<[u8; 4]>>()
            .try_into()
            .unwrap()
    )
}

// Multiply a matrix by a vector in the Rijndael Galois field.
fn rg_field_matrix_vector_mul(matrix: &[[u8; 4]; 4], vector: &[u8; 4]) -> [u8; 4] {
    matrix
        .iter()
        .map(|arr|
            arr.iter().zip(vector.iter())
                .map(|(x, y)| rg_field_mul(*x, *y))
                .fold(0, |acc, x| acc ^ x)
        )
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

// Multiplication within the Rijndael Galois field. This if the field
// GF(2^8) using the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
// In binary, this polynomial is represented as {01}{00011011}, so in
// hex it's 0x11B.
//
// Multiplication by 2 is performed via normal multiplication and
// then--iff that overflows 8 bits--xor with 0x11b. Multiplication by
// consecutive powers of two can be done in the same way. Then to get
// the final result, xor all of the multiples of powers of 2 used to
// form the number. For example, let 2a, 4a, 8a, 16a be the rg_field_mul
// of `a` with 2, 4, 8, and 16 respectively; if b = 0x19 = {00011001},
// then rg_field_mul(a, b) = 16a ^ 8a ^ a.
fn rg_field_mul(a: u8, b: u8) -> u8 {
    // Compute the rg_field_mul of `a` and 2^n for `n` in 0..8.
    let mut a_pow_2 = [0u8; 8];
    a_pow_2[0] = a;

    for i in 1..8 {
        // The mask is 0xff if the high bit of a_pow_2[i - 1] is 1,
        // and 0x00 otherwise. This allows for conditional xor
        // without branching.
        // Use type i8 rather than u8 so we get arithmetic shifting
        // instead of logical shifting (i.e., if we shift right, the
        // bit added is 1 iff the high bit was 1).
        let mask: u8 = ((a_pow_2[i - 1] as i8) >> 7) as u8;
        assert!(mask == 0xff || mask == 0x00);

        // Remember 0x11b represents the irreducible polynomial chosen
        // for AES. But we only xor by it if the 9-th bit would be 1,
        // and since we're implicitly clearing it (by only using u8),
        // we xor by 0x1b instead of 0x11b.
        a_pow_2[i] = (a_pow_2[i - 1] << 1) ^ ((mask & 0x1b) as u8);
    }

    // XOR the appropriate elements of `a_pow_2`. The i-th element is
    // included in the XOR iff the i-th bit of `b` is 1.
    // (ps. i is zero-index).
    let mut result = 0u8;
    let mut c = b;  // We'll shift `c` to read its bits.
    for i in 0..8 {
        // The mask is 0xff if the low bit of `c` is 1, and 0x00 otherwise.
        let mask: u8 = u8::wrapping_sub(0, c & 1);
        assert!(mask == 0xff || mask == 0x00);

        result ^= mask & a_pow_2[i];
        c >>= 1;
    }

    result
}

fn key_expansion(key: [u8; 4 * NUM_KEY_WORDS]) -> [[u8; 4]; STATE_COLS * (NUM_ROUNDS + 1)] {
    let mut keys = [[0u8; 4]; STATE_COLS * (NUM_ROUNDS + 1)];

    for row in 0..NUM_KEY_WORDS {
        for col in 0..4 {
            keys[row][col] = key[4 * row + col];
        }
    }

    for row in NUM_KEY_WORDS..(STATE_COLS * (NUM_ROUNDS + 1)) {
        let mut temp: [u8; 4] = keys[row - 1];

        match row % NUM_KEY_WORDS {
            0 => {
                temp = shift_array_left(&temp, 1)
                    .iter()
                    .map(|x| SUBSTITUTION_TABLE[*x as usize])
                    .zip(ROUND_CONSTANTS[row / NUM_KEY_WORDS].iter())
                    .map(|(x, y)| x ^ y)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap();
            },
            4 => {
                temp = temp.iter().map(|x| SUBSTITUTION_TABLE[*x as usize])
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap();
            }
            _ => ()
        }

        keys[row] = temp.iter().zip(keys[row - NUM_KEY_WORDS].iter()).map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
    }

    keys
}

// Add column `i` of `state` with row `i` of the round key.
// We're doing arithmetic in GF(2^8), so addition is done by xor.
fn add_round_key(state: State, round_key: [[u8; 4]; 4]) -> State {
    transpose_state(
        transpose_state(state).iter()
            .zip(round_key.iter())
            .map(|(state_col, key_arr)| state_col.iter().zip(key_arr.iter()).map(|(s, k)| s ^ k)
                    .collect::<Vec<u8>>().try_into().unwrap()
            )
            .collect::<Vec<[u8; 4]>>()
            .try_into()
            .unwrap()
    )
}

#[cfg(test)]
mod tests {
    ////////////////// Utils for testing //////////////////
    fn state_from_bytes_string(s: &str) -> super::State {
        fn char_to_byte(ch: char) -> u8 {
            match ch {
                '0'..='9' => (ch as u8) - ('0' as u8),
                'a'..='f' => 10 + (ch as u8) - ('a' as u8),
                'A'..='F' => 10 + (ch as u8) - ('F' as u8),
                _ => panic!("Unknown char: {}", ch)
            }
        }

        let single_digits: [u8; 32] = s.chars().map(|ch| char_to_byte(ch)).collect::<Vec<u8>>().try_into().unwrap();
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = (single_digits[2 * i] << 4) | single_digits[2 * i + 1];
        }

        super::state_from_bytes(bytes)
    }

    fn state_to_bytes_string(state: super::State) -> String {
        fn nibble_to_char(n: u8) -> char {
            match n {
                0..=9 => (('0' as u8) + n) as char,
                10..=15 => (('a' as u8) + n - 10) as char,
                _ => panic!("Invalid nibble for casting to char: {}", n)
            }
        }

        fn byte_to_chars(b: u8) -> [char; 2] {
            [nibble_to_char((b & 0xf0) >> 4), nibble_to_char(b & 0x0f)]
        }

        String::from_iter(
            super::state_to_bytes(state)
                .iter()
                .map(|b| byte_to_chars(*b))
                .flatten()
                .collect::<Vec<char>>()
        )
    }

    fn print_state(state: super::State) {
        println!("[");
        for r in 0..super::STATE_ROWS {
            for c in 0..super::STATE_COLS {
                print!("{:02x} ", state[r][c]);
            }

            println!("");
        }
        println!("]");
    }

    //////////////////////// Tests ////////////////////////
    // State to bytes.
    #[test]
    fn state_to_bytes() {
        let state: super::State = [
            utils::hex!("0 1 2 3"),
            utils::hex!("4 5 6 7"),
            utils::hex!("8 9 a b"),
            utils::hex!("c d e f"),
        ];

        let expected: [u8; 16] = [
            0x0, 0x4, 0x8, 0xc,
            0x1, 0x5, 0x9, 0xd,
            0x2, 0x6, 0xa, 0xe,
            0x3, 0x7, 0xb, 0xf,
        ];

        assert_eq!(super::state_to_bytes(state), expected);
    }

    #[test]
    fn state_from_bytes() {
        let bytes: [u8; 16] = [
            0x0, 0x4, 0x8, 0xc,
            0x1, 0x5, 0x9, 0xd,
            0x2, 0x6, 0xa, 0xe,
            0x3, 0x7, 0xb, 0xf,
        ];

        let expected: super::State = [
            utils::hex!("0 1 2 3"),
            utils::hex!("4 5 6 7"),
            utils::hex!("8 9 a b"),
            utils::hex!("c d e f"),
        ];

        assert_eq!(super::state_from_bytes(bytes), expected);
    }

    #[test]
    fn bytes_to_state_and_back() {
        let bytes: [u8; 16] = utils::hex!("01 9f 3a 32 a9 42 4b 1c 98 83 b3 ee 10 3a 80 73");
        assert_eq!(super::state_to_bytes(super::state_from_bytes(bytes)), bytes);
    }

    // Substitute bytes.
    #[test]
    fn substitution_table_inverts() {
        for v in 0..=255 {
            assert_eq!(v, super::INVERSE_SUBSTITUTION_TABLE[super::SUBSTITUTION_TABLE[v as usize] as usize]);
        }
    }

    #[test]
    fn substitute_bytes() {
        let state: super::State = [
            utils::hex!("00 01 02 03"),
            utils::hex!("7f 8f 9f af"),
            utils::hex!("f0 e1 d2 c3"),
            utils::hex!("0f 0e 1e 1f")
        ];

        let expected: super::State = [
            utils::hex!("63 7c 77 7b"),
            utils::hex!("d2 73 db 79"),
            utils::hex!("8c f8 b5 2e"),
            utils::hex!("76 ab 72 c0")
        ];

        assert_eq!(super::substitute_bytes(state), expected);
    }

    // Shift rows
    #[test]
    fn shift_array_left() {
        assert_eq!(super::shift_array_left(&[1, 2, 3, 4], 1), [2, 3, 4, 1]);
        assert_eq!(super::shift_array_left(&[1, 2, 3, 4], 2), [3, 4, 1, 2]);
        assert_eq!(super::shift_array_left(&[1, 2, 3, 4], 3), [4, 1, 2, 3]);
    }

    #[test]
    fn shift_array_right() {
        assert_eq!(super::shift_array_right(&[1, 2, 3, 4], 1), [4, 1, 2, 3]);
        assert_eq!(super::shift_array_right(&[1, 2, 3, 4], 2), [3, 4, 1, 2]);
        assert_eq!(super::shift_array_right(&[1, 2, 3, 4], 3), [2, 3, 4, 1]);
    }

    #[test]
    fn shift_rows() {
        let state: super::State = [
            utils::hex!("0 1 2 3"),
            utils::hex!("4 5 6 7"),
            utils::hex!("8 9 a b"),
            utils::hex!("c d e f"),
        ];

        let expected: super::State = [
            utils::hex!("0 1 2 3"),
            utils::hex!("5 6 7 4"),
            utils::hex!("a b 8 9"),
            utils::hex!("f c d e"),
        ];

        assert_eq!(super::shift_rows(state), expected);
    }

    // Mix columns
    #[test]
    fn transpose_state() {
        let state: super::State = [
            utils::hex!("0 1 2 3"),
            utils::hex!("4 5 6 7"),
            utils::hex!("8 9 a b"),
            utils::hex!("c d e f"),
        ];

        let expected: super::State = [
            utils::hex!("0 4 8 c"),
            utils::hex!("1 5 9 d"),
            utils::hex!("2 6 a e"),
            utils::hex!("3 7 b f"),
        ];

        assert_eq!(super::transpose_state(state), expected);
    }

    #[test]
    fn rg_field_mul() {
        // This case is from the NIST standardization document for AES at
        // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
        // in section 4.2.1.
        assert_eq!(super::rg_field_mul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn mix_columns() {
        // This case is from the NIST standardization document for AES at
        // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
        // in Appendix C.3 round 1.
        let state = state_from_bytes_string("6353e08c0960e104cd70b751bacad0e7");
        let expected = state_from_bytes_string("5f72641557f5bc92f7be3b291db9f91a");

        assert_eq!(super::mix_columns(state), expected);
    }

    // Key expansion
    #[test]
    fn key_expansion() {
        // This case is from the NIST standardization document for AES at
        // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
        // in Appendix A.3.
        let key: [u8; 4 * super::NUM_KEY_WORDS] = utils::hex!("
            60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81
            1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4
        ");

        let keys: [[u8; 4]; super::STATE_COLS * (super::NUM_ROUNDS + 1)] = super::key_expansion(key);

        assert_eq!(keys[0], utils::hex!("60 3d eb 10"));   // Copied from the input key.
        assert_eq!(keys[8], utils::hex!("9b a3 54 11"));   // First key part that's not copied from the input.
        assert_eq!(keys[41], utils::hex!("6c cc 5a 71"));  // Some key part in the middle.
        assert_eq!(keys[59], utils::hex!("70 6c 63 1e"));  // Last part of the last key.
    }

    // Add round key
    #[test]
    fn add_static_round_key() {
        // This case is from the NIST standardization document for AES at
        // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
        // in Appendix C.3, going from round 4 to round 5.
        let round_key: [[u8; 4]; 4] = [
            utils::hex!("ae 87 df f0"),
            utils::hex!("0f f1 1b 68"),
            utils::hex!("a6 8e d5 fb"),
            utils::hex!("03 fc 15 67"),
        ];

        let state = state_from_bytes_string("b2822d81abe6fb275faf103a078c0033");
        let expected = state_from_bytes_string("1c05f271a417e04ff921c5c104701554");

        assert_eq!(super::add_round_key(state, round_key), expected);
    }

    #[test]
    fn add_generated_round_key() {
        // This case is from the NIST standardization document for AES at
        // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
        // in Appendix C.3, going from round 11 to round 12.
        let key: [u8; 4 * super::NUM_KEY_WORDS] = utils::hex!("
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        ");

        let keys: [[u8; 4]; super::STATE_COLS * (super::NUM_ROUNDS + 1)] = super::key_expansion(key);
        let round = 11;
        let round_key: [[u8; 4]; 4] = keys[(super::STATE_COLS * round)..(super::STATE_COLS * (round + 1))]
            .try_into().unwrap();

        let state = state_from_bytes_string("af8690415d6e1dd387e5fbedd5c89013");
        let expected = state_from_bytes_string("5f9c6abfbac634aa50409fa766677653");

        assert_eq!(super::add_round_key(state, round_key), expected);
    }
}