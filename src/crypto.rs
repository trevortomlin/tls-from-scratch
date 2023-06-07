use rand::rngs::OsRng;

use x25519_dalek::{ x25519, X25519_BASEPOINT_BYTES };
use rand_os::rand_core::RngCore;

pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32]
}

pub struct HandshakeKeys {
    pub client_handshake_key: [u8; 32],
    pub server_handshake_key: [u8; 32],
    pub client_handshake_iv: [u8; 12],
    pub server_handshake_iv: [u8; 12]
}

pub fn client_key_exchange_generation() -> KeyPair {
    
    let mut rng = OsRng{};

    let mut private = [0u8; 32];
    rng.fill_bytes(&mut private);

    let public = x25519(private.clone(), X25519_BASEPOINT_BYTES);

    KeyPair {
        public: public,
        private: private
    }

}

pub fn shared_secret(server_pubkey: [u8; 32], client_private: [u8; 32]) -> [u8; 32] {
        
    [0u8; 32]
    
}

pub fn derive_keys(shared_secret: [u8; 32]) -> HandshakeKeys {
    
    HandshakeKeys {
        client_handshake_key: [0u8; 32],
        server_handshake_key: [0u8; 32],
        client_handshake_iv: [0u8; 12],
        server_handshake_iv: [0u8; 12]
    }
    
}

#[cfg(test)]
mod tests {
    use sha2::{Sha384, Digest};
    use super::*;
    use crate::tls_client::server_hello::parse_pubkey;

    #[test]
    fn handshake_keys_calc() {
        let client_hello = include_str!("test/client_hello.txt").replace(" ", "");
        let client_hello = hex::decode(client_hello).unwrap();

        let server_hello = include_str!("test/server_hello.txt").replace(" ", "");
        let server_hello = hex::decode(server_hello).unwrap();

        let server_pubkey = parse_pubkey(&server_hello);

        let expected_key: [u8; 32] = [0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15];
        assert_eq!(server_pubkey, expected_key);

        let client_privkey: [u8; 32] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 
                                        0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                                        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
                                        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                                        0x3e, 0x3f];

        let shared_secret = x25519(client_privkey, server_pubkey);

        let expected_secret: [u8; 32] = [0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf, 0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad, 0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc, 0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24];
        assert_eq!(shared_secret, expected_secret);

        let mut handshake_messages = client_hello[5..].to_vec();
        handshake_messages.extend_from_slice(&server_hello[5..]);

        let mut hasher = Sha384::new();
        hasher.update(&handshake_messages);
        let handshake_hash = hasher.finalize();
        
        let expected_hash: [u8; 48] = [
            0xe0, 0x5f, 0x64, 0xfc, 0xd0, 0x82, 0xbd, 0xb0, 0xdc, 0xe4, 0x73, 0xad, 0xf6, 0x69, 0xc2,
            0x76, 0x9f, 0x25, 0x7a, 0x1c, 0x75, 0xa5, 0x1b, 0x78, 0x87, 0x46, 0x8b, 0x5e, 0x0e, 0x7a,
            0x7d, 0xe4, 0xf4, 0xd3, 0x45, 0x55, 0x11, 0x20, 0x77, 0xf1, 0x6e, 0x07, 0x90, 0x19, 0xd5,
            0xa8, 0x45, 0xbd,
        ];
        assert_eq!(&handshake_hash[..], &expected_hash[..]);

    }

}