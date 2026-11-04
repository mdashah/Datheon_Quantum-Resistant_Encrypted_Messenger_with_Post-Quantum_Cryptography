//! WASM bridge exposing ML-KEM + HKDF + AES-GCM ratchet to the browser.

#[cfg(target_arch = "wasm32")]
mod wasm {
    use pqc_kyber::*;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };
    use hkdf::Hkdf;
    use sha2::Sha256;
    use wasm_bindgen::prelude::*;
    use js_sys::Array;

    fn get_random_bytes() -> rand::rngs::ThreadRng {
        rand::thread_rng()
    }

    #[wasm_bindgen]
    pub fn keypair_wasm() -> Array {
        let mut rng = get_random_bytes();
        let keys = keypair(&mut rng).expect("keypair failed");
        let arr = Array::new();
        arr.push(&JsValue::from_str(&hex::encode(keys.public)));
        arr.push(&JsValue::from_str(&hex::encode(keys.secret)));
        arr
    }

    #[wasm_bindgen]
    pub fn encapsulate_wasm(peer_pk_hex: &str) -> Array {
        let pk_bytes = hex::decode(peer_pk_hex).expect("bad pk hex");
        let mut rng = get_random_bytes();
        let (ct, ss) = encapsulate(&pk_bytes, &mut rng).expect("encapsulate failed");
        let arr = Array::new();
        arr.push(&JsValue::from_str(&hex::encode(ct)));
        arr.push(&JsValue::from_str(&hex::encode(ss)));
        arr
    }

    #[wasm_bindgen]
    pub fn decapsulate_wasm(ct_hex: &str, sk_hex: &str) -> String {
        let ct_bytes = hex::decode(ct_hex).expect("bad ct hex");
        let sk_bytes = hex::decode(sk_hex).expect("bad sk hex");
        let ss = decapsulate(&ct_bytes, &sk_bytes).expect("decapsulate failed");
        hex::encode(ss)
    }

    #[wasm_bindgen]
    pub fn hkdf_32_wasm(ikm_hex: &str, info: &str) -> String {
        let ikm = hex::decode(ikm_hex).expect("bad ikm");
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm).expect("hkdf");
        hex::encode(okm)
    }

    #[wasm_bindgen]
    pub fn ratchet_step_wasm(key_hex: &str) -> String {
        let key_bytes = hex::decode(key_hex).expect("bad key hex");
        let hk = Hkdf::<Sha256>::new(None, &key_bytes);
        let mut okm = [0u8; 32];
        hk.expand(b"ratchet", &mut okm).expect("hkdf");
        hex::encode(okm)
    }

    #[wasm_bindgen]
    pub fn encrypt_wasm(key_hex: &str, plaintext: &str) -> Array {
        let kb = hex::decode(key_hex).expect("bad key");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kb));
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .expect("encrypt");
        let arr = Array::new();
        arr.push(&JsValue::from_str(&hex::encode(nonce_bytes)));
        arr.push(&JsValue::from_str(&hex::encode(ct)));
        arr
    }

    #[wasm_bindgen]
    pub fn decrypt_wasm(key_hex: &str, nonce_hex: &str, ct_hex: &str) -> JsValue {
        let kb = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return JsValue::NULL };
        let nb = match hex::decode(nonce_hex) { Ok(n) => n, Err(_) => return JsValue::NULL };
        let ct = match hex::decode(ct_hex) { Ok(c) => c, Err(_) => return JsValue::NULL };
        
        if kb.len() != 32 || nb.len() != 12 {
            return JsValue::NULL;
        }
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kb));
        match cipher.decrypt(Nonce::from_slice(&nb), ct.as_ref()) {
            Ok(pt) => JsValue::from_str(&String::from_utf8_lossy(&pt)),
            Err(_) => JsValue::NULL,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    pub fn hkdf_32(ikm: &[u8], info: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm).expect("hkdf expand");
        okm
    }

    pub fn ratchet_step(key: &[u8; 32]) -> [u8; 32] {
        hkdf_32(key, "ratchet")
    }

    pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_bytes: [u8; 12] = rand::random();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .expect("encrypt");
        (nonce_bytes, ct)
    }

    pub fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;