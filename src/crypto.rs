use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

pub fn client_key_exchange_generation() -> Keypair {
    let mut csprng = OsRng{};
    Keypair::generate(&mut csprng)
}