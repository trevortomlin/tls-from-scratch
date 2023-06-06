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