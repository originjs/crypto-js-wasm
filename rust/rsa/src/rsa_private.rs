use super::*;

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;

#[wasm_bindgen]
#[derive(Debug)]
pub struct RsaPrivate {
    pri_instance: RsaPrivateKey,
    pri_pem: String,
    pub_pem: String,
}

#[wasm_bindgen]
impl RsaPrivate {
    #[wasm_bindgen(constructor)]
    pub fn new(bits: Option<usize>, input_key_pem: Option<String>) -> Self {
        utils::set_panic_hook();
        let mut rng = rand::thread_rng();

        let pri_instance = match input_key_pem {
            Some(key_pem) => RsaPrivateKey::from_pkcs8_pem(&key_pem)
                .expect("Failed to read private key pem file"),
            _ => match bits {
                Some(bits) => RsaPrivateKey::new(&mut rng, bits).expect("Fialed to generate keys"),
                _ => panic!("Neither bit size nor key file is provided"),
            }
        };

        let pri_pem = pri_instance
            .to_pkcs8_pem(LineEnding::default())
            .expect("Failed to transform keys to pem")
            .to_string();
        let pub_pem = pri_instance
            .to_public_key()
            .to_public_key_pem(LineEnding::default())
            .expect("Failed to transform keys to pem")
            .to_string();
        Self {
            pri_instance,
            pri_pem,
            pub_pem,
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], padding_scheme: &str, hash_function: &str) -> Vec<u8> {
        let padding = utils::padding_util("encrypt", padding_scheme, hash_function, b"");

        self.pri_instance
            .decrypt(padding, ciphertext)
            .expect("Failed to decrypt the ciphertext!")
    }

    pub fn sign(&self, digest: &[u8], padding_scheme: &str, hash_function: &str) -> Vec<u8> {
        let padding = utils::padding_util("sign", padding_scheme, hash_function, digest);

        self.pri_instance.sign(padding, &digest).expect("Failed to sign digest")
    }

    #[wasm_bindgen(js_name = getPrivateKeyContent)]
    pub fn get_private_key_content(&self, fmt: &str) -> JsValue {
        match fmt {
            "pem" => JsValue::from_str(&self.pri_pem),
            "der" => {
                serde_wasm_bindgen::to_value(
                    &self.pri_instance
                        .to_pkcs8_der()
                        .expect("Failed to transform private key to bytes")
                        .as_der()
                        .to_vec()
                ).unwrap()
            },
            _ => panic!("Only pem and der supported")
        }
    }

    #[wasm_bindgen(js_name = getPublicKeyPem)]
    pub fn get_public_key_pem(&self) -> String {
        self.pub_pem.clone()
    }
}

#[cfg(test)]
mod rsa_private_tests {
    use super::*;

    #[test]
    fn can_new_with_bits() {
        let rsa_private = RsaPrivate::new(Some(1024), None);
        assert_eq!(rsa_private.pri_pem.is_empty(), false);
    }

    #[test]
    #[should_panic]
    fn cannot_new_with_empty_key() {
        RsaPrivate::new(None, Some(String::from("")));
    }

    #[test]
    fn can_get_public_content() {
        let rsa_private = RsaPrivate::new(Some(1024), None);
        assert_ne!(rsa_private.get_public_key_pem(), String::from(""));
    }
}
