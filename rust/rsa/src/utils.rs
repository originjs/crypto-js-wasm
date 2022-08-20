use rsa::{Hash, PaddingScheme};
use rand::rngs::ThreadRng;

#[allow(unused)] // allow function unused
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn padding_util(op: &str, padding_scheme: &str, hash_function: &str, digest: &[u8]) -> PaddingScheme {
    match padding_scheme {
        "PKCS1V15" if op == "encrypt" => PaddingScheme::new_pkcs1v15_encrypt(),
        "OAEP" if op == "encrypt" => match hash_function {
            "MD5" => PaddingScheme::new_oaep::<md5::Md5>(),
            "SHA1" => PaddingScheme::new_oaep::<sha1::Sha1>(),
            "SHA224" => PaddingScheme::new_oaep::<sha2::Sha224>(),
            "SHA256" => PaddingScheme::new_oaep::<sha2::Sha256>(),
            "SHA384" => PaddingScheme::new_oaep::<sha2::Sha384>(),
            "SHA512" => PaddingScheme::new_oaep::<sha2::Sha512>(),
            "RIPEMD160" => PaddingScheme::new_oaep::<ripemd::Ripemd160>(),
            _ => panic!("The hash function is not supported."),
        },
        "PKCS1V15" if op == "sign" => match hash_function {
            "MD5" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::MD5)),
            "SHA1" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1)),
            "SHA224" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_224)),
            "SHA256" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
            "SHA384" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_384)),
            "SHA512" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_512)),
            "RIPEMD160" => PaddingScheme::new_pkcs1v15_sign(Some(Hash::RIPEMD160)),
            _ => panic!("The hash function is not supported."),
        },
        "PSS" if op == "sign" => match hash_function {
            "MD5" => PaddingScheme::new_pss_with_salt::<md5::Md5, ThreadRng>(rand::thread_rng(), digest.len()),
            "SHA1" => PaddingScheme::new_pss_with_salt::<sha1::Sha1, ThreadRng>(rand::thread_rng(), digest.len()),
            "SHA224" => PaddingScheme::new_pss_with_salt::<sha2::Sha224, ThreadRng>(rand::thread_rng(), digest.len()),
            "SHA256" => PaddingScheme::new_pss_with_salt::<sha2::Sha256, ThreadRng>(rand::thread_rng(), digest.len()),
            "SHA384" => PaddingScheme::new_pss_with_salt::<sha2::Sha384, ThreadRng>(rand::thread_rng(), digest.len()),
            "SHA512" => PaddingScheme::new_pss_with_salt::<sha2::Sha512, ThreadRng>(rand::thread_rng(), digest.len()),
            "RIPEMD160" => PaddingScheme::new_pss_with_salt::<ripemd::Ripemd160, ThreadRng>(rand::thread_rng(), digest.len()),
            _ => panic!("The hash function is not supported."),
        },
        _ => panic!("The padding scheme is not supported."),
    }
}
