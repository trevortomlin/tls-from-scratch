use x25519_dalek::PublicKey;

pub fn parse_pubkey(server_hello: &[u8]) -> PublicKey {
    let mut iter = server_hello.iter()
                                                          .skip(5)
                                                          .skip(4)
                                                          .skip(2)
                                                          .skip(32)
                                                          .skip(32)
                                                          .skip(2)
                                                          .skip(1)
                                                          .skip(2)
                                                          .skip_while(|&x| *x != 0x00u8 && *x != 0x33u8)
                                                          .skip(2)
                                                          .skip(2)
                                                          .skip(2)
                                                          .skip(2)
                                                          .skip(2)
                                                          .skip(2)
                                                          .skip(2);

    let mut pubkey = [0; 32];

    for i in 0..32 {
        pubkey[i] = *iter.next().unwrap();
    }

    PublicKey::from(pubkey)
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pubkey() {

        let server_hello = include_str!("../test/server_hello.txt").replace(" ", "");
        let server_hello = hex::decode(server_hello).unwrap();

        let pubkey = parse_pubkey(&server_hello);

        let expected_key: [u8; 32] = [0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15];
        assert_eq!(pubkey.as_bytes(), &expected_key);

    }

}