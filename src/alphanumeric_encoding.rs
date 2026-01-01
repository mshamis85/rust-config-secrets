use crate::error::ConfigSecretsError;

// 0-9 (10) + A-Z (26) + a-y (25) = 61 single chars.
// indices 0..60.
// 61 -> za
// 62 -> zb
// 63 -> zc

fn value_to_str(val: u8) -> &'static str {
    match val {
        0 => "0", 1 => "1", 2 => "2", 3 => "3", 4 => "4", 5 => "5", 6 => "6", 7 => "7", 8 => "8", 9 => "9",
        10 => "A", 11 => "B", 12 => "C", 13 => "D", 14 => "E", 15 => "F", 16 => "G", 17 => "H", 18 => "I", 19 => "J",
        20 => "K", 21 => "L", 22 => "M", 23 => "N", 24 => "O", 25 => "P", 26 => "Q", 27 => "R", 28 => "S", 29 => "T",
        30 => "U", 31 => "V", 32 => "W", 33 => "X", 34 => "Y", 35 => "Z",
        36 => "a", 37 => "b", 38 => "c", 39 => "d", 40 => "e", 41 => "f", 42 => "g", 43 => "h", 44 => "i", 45 => "j",
        46 => "k", 47 => "l", 48 => "m", 49 => "n", 50 => "o", 51 => "p", 52 => "q", 53 => "r", 54 => "s", 55 => "t",
        56 => "u", 57 => "v", 58 => "w", 59 => "x", 60 => "y",
        61 => "za",
        62 => "zb",
        63 => "zc",
        _ => panic!("Invalid 6-bit value"),
    }
}

fn char_to_value(c: char) -> Result<u8, ConfigSecretsError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'A'..='Z' => Ok(c as u8 - b'A' + 10),
        'a'..='y' => Ok(c as u8 - b'a' + 36),
        _ => Err(ConfigSecretsError::InvalidEncoding(format!("Invalid character: {}", c))),
    }
}

pub fn encode(data: &[u8]) -> Result<String, ConfigSecretsError> {
    let mut encoded = String::with_capacity(data.len() * 4 / 3 + 4);
    let mut bit_buffer: u32 = 0;
    let mut bit_count = 0;

    for &byte in data {
        bit_buffer = (bit_buffer << 8) | byte as u32;
        bit_count += 8;

        while bit_count >= 6 {
            bit_count -= 6;
            let val = ((bit_buffer >> bit_count) & 0x3F) as u8;
            encoded.push_str(value_to_str(val));
        }
    }

    if bit_count > 0 {
        let shift = 6 - bit_count;
        let val = ((bit_buffer << shift) & 0x3F) as u8;
        encoded.push_str(value_to_str(val));
    }

    Ok(encoded)
}

pub fn decode(input: &str) -> Result<Vec<u8>, ConfigSecretsError> {
    let mut decoded = Vec::with_capacity(input.len() * 3 / 4);
    let mut bit_buffer: u32 = 0;
    let mut bit_count = 0;
    
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        let val = if c == 'z' {
            match chars.next() {
                Some('a') => 61,
                Some('b') => 62,
                Some('c') => 63,
                Some(other) => return Err(ConfigSecretsError::InvalidEncoding(format!("Invalid escape sequence: z{}", other))),
                None => return Err(ConfigSecretsError::InvalidEncoding("Incomplete escape sequence 'z'".to_string())),
            }
        } else {
            char_to_value(c)?
        };

        bit_buffer = (bit_buffer << 6) | val as u32;
        bit_count += 6;

        if bit_count >= 8 {
            bit_count -= 8;
            let byte = ((bit_buffer >> bit_count) & 0xFF) as u8;
            decoded.push(byte);
        }
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_basic() {
        let data = b"Hello World";
        let encoded = encode(data).unwrap();
        assert!(encoded.chars().all(|c| c.is_alphanumeric()));
        
        let decoded = decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_encode_decode_binary() {
        let data = vec![0xFF, 0x00, 0xAA, 0x55, 61, 62, 63];
        let encoded = encode(&data).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_escape_sequences() {
        let input = vec![255, 255, 255];
        let encoded = encode(&input).unwrap();
        assert_eq!(encoded, "zczczczc");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(input, decoded);
    }
    
    #[test]
    fn test_padding_scenarios() {
        // 1 byte (8 bits) -> 1x6 bits + 2 bits.
        let data1 = vec![0xFF];
        let enc1 = encode(&data1).unwrap();
        assert_eq!(enc1, "zcm");
        assert_eq!(decode(&enc1).unwrap(), data1);

        // 2 bytes (16 bits) -> 2x6 bits + 4 bits.
        let data2 = vec![0xFF, 0xFF];
        let enc2 = encode(&data2).unwrap();
        assert_eq!(enc2, "zczcy");
        assert_eq!(decode(&enc2).unwrap(), data2);
    }

    #[test]
    fn test_decoding_ignores_padding_bits() {
        let input = "zcn"; 
        let decoded = decode(input).unwrap();
        assert_eq!(decoded, vec![0xFF]);
    }

    #[test]
    fn test_invalid_char() {
        assert!(decode("0!").is_err());
    }

    #[test]
    fn test_invalid_escape() {
        assert!(decode("zd").is_err());
        assert!(decode("z").is_err());
    }
}
