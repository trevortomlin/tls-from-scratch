use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub struct KeyPair {
    pub pubkey: PublicKey,
    pub privkey: EphemeralSecret,
}

pub fn client_key_exchange_generation() -> KeyPair {
    
    let private_key = EphemeralSecret::new(OsRng);
    let public_key = PublicKey::from(&private_key);

    KeyPair {
        pubkey: public_key,
        privkey: private_key,
    }
}

pub fn shared_secret(server_pubkey: PublicKey, client_private: EphemeralSecret) -> SharedSecret {
        
    client_private.diffie_hellman(&server_pubkey)
    
}