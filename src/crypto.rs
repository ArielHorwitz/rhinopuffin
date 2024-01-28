use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

const NONCE_SIZE: usize = 12;

pub fn encrypt(plaintext: &[u8], key: Key) -> Result<Vec<u8>> {
    let nonce_data: [u8; NONCE_SIZE] = thread_rng().gen();
    let mut ciphertext = key
        .cipher
        .encrypt(Nonce::from_slice(&nonce_data), plaintext)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    ciphertext.extend_from_slice(&nonce_data);
    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], key: Key) -> Result<Vec<u8>> {
    let split_at = ciphertext.len().saturating_sub(NONCE_SIZE);
    let (ciphertext, nonce_data) = ciphertext.split_at(split_at);
    let plaintext = key
        .cipher
        .decrypt(Nonce::from_slice(nonce_data), ciphertext)
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    Ok(plaintext)
}

pub struct Key {
    cipher: Aes256Gcm,
}

impl Key {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key: [u8; 32] = Sha256::digest(key).into();
        let cipher = Aes256Gcm::new_from_slice(&key).context("key from slice")?;
        Ok(Self { cipher })
    }
}
