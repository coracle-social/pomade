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
