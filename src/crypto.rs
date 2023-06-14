use rand::rngs::OsRng;
use x25519_dalek::{ x25519, X25519_BASEPOINT_BYTES };
use rand_os::rand_core::RngCore;
use sha2::{Sha384, Digest};
use hkdf::Hkdf;
use hex_literal::hex;

pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32]
}

pub struct HandshakeKeys {
    pub client_handshake_key: Vec<u8>,
    pub server_handshake_key: Vec<u8>,
    pub client_handshake_iv: Vec<u8>,
    pub server_handshake_iv: Vec<u8>
}

pub struct HkdfLabel {
    pub length: u16,
    pub label: Vec<u8>,
    pub context: Vec<u8>,
}
/*
 struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;
*/
impl HkdfLabel {
    pub fn new(length: u16, label: Vec<u8>, context: Vec<u8>) -> Self {
        HkdfLabel {
            length: length,
            label: label,
            context: context
        }
    }
    
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&self.length.to_be_bytes());
        //hkdf_label.push(0x0d); // This is carriage return idk why it is added
        // push length of tls13 + label
        hkdf_label.push(("tls13 ".len() + &self.label.len()) as u8);
        hkdf_label.extend_from_slice("tls13 ".as_bytes());
        hkdf_label.extend_from_slice(&self.label);
        hkdf_label.extend_from_slice(&(self.context.len() as u8).to_be_bytes()); // This doesn't seem to be in any of the specs but its in the illustrated tls1.3 guide
        hkdf_label.extend_from_slice(&self.context);
        hkdf_label
    }
}
// Expand: HKDF-Expand(PRK, info, L) -> OKM
// Extract: HKDF-Extract(salt, IKM) -> PRK

// HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
fn hkdf_expand_label(secret: &[u8], label: HkdfLabel) -> [u8; 48] {
    let hkdf = Hkdf::<Sha384>::from_prk(secret).unwrap();
    let mut okm = [0u8; 48];
    hkdf.expand(&label.to_be_bytes(), &mut okm).unwrap();
    okm
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
        
    x25519(client_private, server_pubkey)
    
}

pub fn derive_keys(shared_secret: [u8; 32], handshake_hash: [u8; 48]) -> HandshakeKeys {
    // Early Secret
    let (early_secret, _) = Hkdf::<Sha384>::extract(Some(&[0u8; 2]), &[0u8; 48]);

    // Empty Hash
    let empty_hash = Sha384::digest(&[]);

    // Derived Secret
    let label = b"derived".to_vec();
    let context = empty_hash.to_vec();
    let length = 48u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let derived_secret = hkdf_expand_label(&early_secret, hkdf_label);

    // Handshake Secret
    let (handshake_secret, _) = Hkdf::<Sha384>::extract(Some(&derived_secret), &shared_secret);

    // Client Secret
    let label = b"c hs traffic".to_vec();
    let context = handshake_hash.to_vec();
    let length = 48u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let client_secret = hkdf_expand_label(&handshake_secret, hkdf_label);

    // Server Secret
    let label = b"s hs traffic".to_vec();
    let context = handshake_hash.to_vec();
    let length = 48u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let server_secret = hkdf_expand_label(&handshake_secret, hkdf_label);

    // Client Handshake Key
    let label = b"key".to_vec();
    let context = b"".to_vec();
    let length = 32u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let client_handshake_key = &hkdf_expand_label(&client_secret, hkdf_label)[..length as usize];

    // Server Handshake Key
    let label = b"key".to_vec();
    let context = b"".to_vec();
    let length = 32u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let server_handshake_key = &hkdf_expand_label(&server_secret, hkdf_label)[..length as usize];

    // Client Handshake IV
    let label = b"iv".to_vec();
    let context = b"".to_vec();
    let length = 12u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let client_handshake_iv = &hkdf_expand_label(&client_secret, hkdf_label)[..length as usize];

    // Server Handshake IV
    let label = b"iv".to_vec();
    let context = b"".to_vec();
    let length = 12u16;

    let hkdf_label = HkdfLabel::new(length, label, context);

    let server_handshake_iv = &hkdf_expand_label(&server_secret, hkdf_label)[..length as usize];

    HandshakeKeys {
        client_handshake_key: client_handshake_key.to_vec(),
        server_handshake_key: server_handshake_key.to_vec(),
        client_handshake_iv: client_handshake_iv.to_vec(),
        server_handshake_iv: server_handshake_iv.to_vec()
    }
    
}

pub fn hash_handshake(client_hello: Vec<u8>, server_hello: Vec<u8>) -> [u8; 48] {
    
    let mut handshake_messages = client_hello[5..].to_vec();
    handshake_messages.extend_from_slice(&server_hello[5..]);

    let mut hasher = Sha384::new();
    hasher.update(&handshake_messages);
    let hash = hasher.finalize();

    let mut hash_bytes = [0u8; 48];
    hash_bytes.copy_from_slice(&hash[..48]);
    hash_bytes
    
}

#[cfg(test)]
mod tests {
    use sha2::{Sha384, Digest};
    use super::*;
    use crate::tls_client::server_hello::parse_pubkey;
    use hex_literal::hex;

    #[test]
    fn test_shared_secret() {
        let server_hello = include_str!("test/server_hello.txt").replace(" ", "");
        let server_hello = hex::decode(server_hello).unwrap();

        let server_pubkey = parse_pubkey(&server_hello);

        let client_privkey: [u8; 32] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 
                                        0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                                        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
                                        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                                        0x3e, 0x3f];

        let expected_shared_secret: [u8; 32] = [0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf,
                                                0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad,
                                                0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc,
                                                0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24];

        let shared_secret = shared_secret(server_pubkey, client_privkey);

        assert_eq!(shared_secret, expected_shared_secret);
    }

    #[test]
    fn test_handshake_hash() {
        let client_hello = include_str!("test/client_hello.txt").replace(" ", "");
        let client_hello = hex::decode(client_hello).unwrap();

        let server_hello = include_str!("test/server_hello.txt").replace(" ", "");
        let server_hello = hex::decode(server_hello).unwrap();

        let handshake_hash = hash_handshake(client_hello, server_hello);
        
        let expected_hash: [u8; 48] = [
            0xe0, 0x5f, 0x64, 0xfc, 0xd0, 0x82, 0xbd, 0xb0, 0xdc, 0xe4, 0x73, 0xad, 0xf6, 0x69, 0xc2,
            0x76, 0x9f, 0x25, 0x7a, 0x1c, 0x75, 0xa5, 0x1b, 0x78, 0x87, 0x46, 0x8b, 0x5e, 0x0e, 0x7a,
            0x7d, 0xe4, 0xf4, 0xd3, 0x45, 0x55, 0x11, 0x20, 0x77, 0xf1, 0x6e, 0x07, 0x90, 0x19, 0xd5,
            0xa8, 0x45, 0xbd,
        ];
        assert_eq!(&handshake_hash[..], &expected_hash[..]);
    }

    #[test]
    fn early_secret_test() {
        let (early_secret, _) = Hkdf::<Sha384>::extract(Some(&[0u8; 2]), &[0u8; 48]);

        let early_secret_expected: [u8; 48] = [
            0x7e, 0xe8, 0x20, 0x6f, 0x55, 0x70, 0x02, 0x3e, 0x6d, 0xc7, 0x51, 0x9e, 0xb1, 0x07, 0x3b,
            0xc4, 0xe7, 0x91, 0xad, 0x37, 0xb5, 0xc3, 0x82, 0xaa, 0x10, 0xba, 0x18, 0xe2, 0x35, 0x7e,
            0x71, 0x69, 0x71, 0xf9, 0x36, 0x2f, 0x2c, 0x2f, 0xe2, 0xa7, 0x6b, 0xfd, 0x78, 0xdf, 0xec,
            0x4e, 0xa9, 0xb5,
        ];
        assert_eq!(&early_secret[..], &early_secret_expected[..]);
    }

    #[test]
    fn empty_hash_test() {
        let empty_hash = Sha384::digest(&[]);

        let expected_empty_hash: [u8; 48] = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
            0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
            0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
            0x98, 0xb9, 0x5b,
        ];

        assert_eq!(&empty_hash[..], &expected_empty_hash[..]);
    }

    #[test]
    fn derived_secret_test() {

        let early_secret: [u8; 48] = [
            0x7e, 0xe8, 0x20, 0x6f, 0x55, 0x70, 0x02, 0x3e, 0x6d, 0xc7, 0x51, 0x9e, 0xb1, 0x07, 0x3b,
            0xc4, 0xe7, 0x91, 0xad, 0x37, 0xb5, 0xc3, 0x82, 0xaa, 0x10, 0xba, 0x18, 0xe2, 0x35, 0x7e,
            0x71, 0x69, 0x71, 0xf9, 0x36, 0x2f, 0x2c, 0x2f, 0xe2, 0xa7, 0x6b, 0xfd, 0x78, 0xdf, 0xec,
            0x4e, 0xa9, 0xb5,
        ];

        let empty_hash: [u8; 48] = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
            0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
            0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
            0x98, 0xb9, 0x5b,
        ];

        let label = b"derived".to_vec();
        let context = empty_hash.to_vec();
        let length = 48u16;
    
        let hkdf_label = HkdfLabel::new(length, label, context);

        let derived_secret = hkdf_expand_label(&early_secret, hkdf_label);

        let expected_derived_secret = hex!(
            "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b"
        );
    
        assert_eq!(&derived_secret[..], &expected_derived_secret[..]);
    }

    #[test]
    fn handshake_secret_test() {
        let shared_secret: [u8; 32] = [0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf, 0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad, 0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc, 0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24];
        let derived_secret = hex!(
            "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b"
        );

        let (handshake_secret, _) = Hkdf::<Sha384>::extract(Some(&derived_secret), &shared_secret);

        let expected_handshake_secret = hex!("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");

        assert_eq!(&handshake_secret[..], &expected_handshake_secret[..]);
    }

    #[test]
    fn client_secret_test() {
        let handshake_hash = hex!("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");
        let handshake_secret = hex!("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");

        let label = b"c hs traffic".to_vec();
        let context = handshake_hash.to_vec();
        let length = 48u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let client_secret = hkdf_expand_label(&handshake_secret, hkdf_label);

        let expected_client_secret = hex!("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");

        assert_eq!(&client_secret[..], &expected_client_secret[..]);
    }

    #[test]
    fn server_secret_test() {
        let handshake_hash = hex!("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");
        let handshake_secret = hex!("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");

        let label = b"s hs traffic".to_vec();
        let context = handshake_hash.to_vec();
        let length = 48u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let server_secret = hkdf_expand_label(&handshake_secret, hkdf_label);

        let expected_server_secret = hex!("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");

        assert_eq!(&server_secret[..], &expected_server_secret[..]);
    }

    #[test]
    fn client_handshake_key() {
        let client_secret = hex!("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");
        let label = b"key".to_vec();
        let context = b"".to_vec();
        let length = 32u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let client_handshake_key = &hkdf_expand_label(&client_secret, hkdf_label)[..length as usize];

        let expected_client_handshake_key = hex!("1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69");
        assert_eq!(&client_handshake_key[..], &expected_client_handshake_key[..]);
    }

    #[test]
    fn server_handshake_key() {
        let server_secret = hex!("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");
        let label = b"key".to_vec();
        let context = b"".to_vec();
        let length = 32u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let server_handshake_key = &hkdf_expand_label(&server_secret, hkdf_label)[..length as usize];

        let expected_server_handshake_key = hex!("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f");
        assert_eq!(&server_handshake_key[..], &expected_server_handshake_key[..]);
    }

    #[test]
    fn client_handshake_iv() {
        let client_secret = hex!("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");
        let label = b"iv".to_vec();
        let context = b"".to_vec();
        let length = 12u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let client_handshake_iv = &hkdf_expand_label(&client_secret, hkdf_label)[..length as usize];

        let expected_client_handshake_iv = hex!("4256d2e0e88babdd05eb2f27");
        assert_eq!(&client_handshake_iv[..], &expected_client_handshake_iv[..]);
    }

    #[test]
    fn server_handshake_iv() {
        let server_secret = hex!("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");
        let label = b"iv".to_vec();
        let context = b"".to_vec();
        let length = 12u16;

        let hkdf_label = HkdfLabel::new(length, label, context);

        let server_handshake_iv = &hkdf_expand_label(&server_secret, hkdf_label)[..length as usize];

        let expected_server_handshake_iv = hex!("9563bc8b590f671f488d2da3");
        assert_eq!(&server_handshake_iv[..], &expected_server_handshake_iv[..]);
    }

    #[test]
    fn handshake_keys_calc() {

        let shared_secret: [u8; 32] = [0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf, 0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad, 0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc, 0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24];
        let handshake_hash = hex!("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");

        let expected_handshake_keys = HandshakeKeys {
            client_handshake_key: hex!("1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69").to_vec(),
            server_handshake_key: hex!("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f").to_vec(),
            client_handshake_iv: hex!("4256d2e0e88babdd05eb2f27").to_vec(),
            server_handshake_iv: hex!("9563bc8b590f671f488d2da3").to_vec(),
        };

        let handshake_keys = derive_keys(shared_secret, handshake_hash);


        assert_eq!(handshake_keys.client_handshake_iv, expected_handshake_keys.client_handshake_iv);
        assert_eq!(handshake_keys.server_handshake_iv, expected_handshake_keys.server_handshake_iv);
        assert_eq!(handshake_keys.client_handshake_key, expected_handshake_keys.client_handshake_key);
        assert_eq!(handshake_keys.server_handshake_key, expected_handshake_keys.server_handshake_key);

    }

}