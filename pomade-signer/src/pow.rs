/// Count the number of leading zero bits in a 32-byte hash.
pub fn get_pow(id: &[u8; 32]) -> u32 {
    let mut count = 0;

    for &byte in id {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pow_all_zeros() {
        let id = [0u8; 32];
        assert_eq!(get_pow(&id), 256); // 32 bytes * 8 bits
    }

    #[test]
    fn test_get_pow_no_zeros() {
        let id = [0xffu8; 32];
        assert_eq!(get_pow(&id), 0); // No leading zeros
    }

    #[test]
    fn test_get_pow_one_leading_zero_byte() {
        let mut id = [0u8; 32];
        id[0] = 0;
        id[1] = 0x80; // 10000000 - 1 leading zero bit
        assert_eq!(get_pow(&id), 8 + 0); // First byte is 0 (8 zeros), second byte starts with 1

        id[1] = 0x40; // 01000000 - 2 leading zero bits
        assert_eq!(get_pow(&id), 8 + 1);

        id[1] = 0x01; // 00000001 - 7 leading zero bits
        assert_eq!(get_pow(&id), 8 + 7);
    }

    #[test]
    fn test_get_pow_multiple_zero_bytes() {
        let mut id = [0xffu8; 32];
        id[0] = 0;
        id[1] = 0;
        id[2] = 0x80;
        assert_eq!(get_pow(&id), 16 + 0); // 2 zero bytes + 0 from next
    }

    #[test]
    fn test_get_pow_various_patterns() {
        // 0x00 = 00000000 = 8 leading zeros
        assert_eq!(
            get_pow(&[
                0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]),
            8
        );

        // 0x01 = 00000001 = 7 leading zeros
        assert_eq!(
            get_pow(&[
                0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]),
            7
        );

        // 0x7f = 01111111 = 1 leading zero
        assert_eq!(
            get_pow(&[
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]),
            1
        );

        // 0x80 = 10000000 = 0 leading zeros
        assert_eq!(
            get_pow(&[
                0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            ]),
            0
        );
    }

    #[test]
    fn test_get_pow_realistic_pow_20() {
        // Simulate a hash with 20 leading zeros (typical for PoW 20)
        // 20 zeros = 2 full zero bytes + 4 bits in third byte
        let mut id = [0xffu8; 32];
        id[0] = 0x00;
        id[1] = 0x00;
        id[2] = 0x0f; // 00001111 = 4 leading zeros
        assert_eq!(get_pow(&id), 20);
    }

    #[test]
    fn test_get_pow_edge_cases() {
        // Single bit patterns
        let mut id = [0xffu8; 32];

        // 0x80 = 10000000 (0 leading zeros)
        id[0] = 0x80;
        assert_eq!(get_pow(&id), 0);

        // 0x40 = 01000000 (1 leading zero)
        id[0] = 0x40;
        assert_eq!(get_pow(&id), 1);

        // 0x20 = 00100000 (2 leading zeros)
        id[0] = 0x20;
        assert_eq!(get_pow(&id), 2);

        // 0x10 = 00010000 (3 leading zeros)
        id[0] = 0x10;
        assert_eq!(get_pow(&id), 3);

        // 0x08 = 00001000 (4 leading zeros)
        id[0] = 0x08;
        assert_eq!(get_pow(&id), 4);

        // 0x04 = 00000100 (5 leading zeros)
        id[0] = 0x04;
        assert_eq!(get_pow(&id), 5);

        // 0x02 = 00000010 (6 leading zeros)
        id[0] = 0x02;
        assert_eq!(get_pow(&id), 6);

        // 0x01 = 00000001 (7 leading zeros)
        id[0] = 0x01;
        assert_eq!(get_pow(&id), 7);
    }
}
