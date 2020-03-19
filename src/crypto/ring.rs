use crate::crypto;

use crate::errors::RPMError;

use ::ring::signature as risig;

use ::ring as ri;

#[derive(Debug)]
pub struct Signer {
    secret_signing_key: risig::RsaKeyPair,
    rng: ri::rand::SystemRandom,
}

impl crypto::Signing<crypto::RSA_SHA256> for Signer {
    type Signature = Vec<u8>;

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError> {
        let mut signature = vec![0; self.secret_signing_key.public_modulus_len()];

        self.secret_signing_key
            .sign(&risig::RSA_PKCS1_SHA256, &self.rng, data, &mut signature)
            .map_err(|e| format!("Failed create signature: {}", e))?;
        Ok(signature)
    }
}

impl crypto::LoaderPkcs8 for Signer {
    fn load_from_pkcs8(bytes: &[u8]) -> Result<Self, RPMError> {
        let secret_signing_key = risig::RsaKeyPair::from_pkcs8(&bytes)
            .map_err(|e| format!("Failed  to load RSA keypair: {}", e))?;
        Ok(Self {
            secret_signing_key,
            rng: ri::rand::SystemRandom::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Verifier {
    public_key_pkcs1: Vec<u8>,
    // : risig::RsaPublicKeyComponents<&'v [u8]>;
}

impl crypto::Verifying<crypto::RSA_SHA256> for Verifier {
    type Signature = Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError> {
        let public_key = risig::UnparsedPublicKey::new(
            &risig::RSA_PKCS1_2048_8192_SHA256,
            self.public_key_pkcs1.as_slice(),
        );
        public_key
            .verify(data, signature.as_ref())
            .map_err(|e| format!("Failed to verify: {}", e))?;
        Ok(())
    }
}

impl crypto::LoaderPkcs8 for Verifier {
    /// load the private key for signing
    fn load_from_pkcs8(bytes: &[u8]) -> Result<Self, RPMError> {
        // TODO not so pretty, need to validate here
        Ok(Self {
            public_key_pkcs1: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {

    use crate::crypto::{Algorithm, LoaderPkcs8, Signing, Verifying, RSA_SHA256};
    use crate::errors::RPMError;
    // use ::pem;

    use crate::signature::test::{load_pkcs8_keys, roundtrip_sign_verify};

    #[test]
    fn sign_verify_round() -> Result<(), Box<dyn std::error::Error>> {
        let (pkcs8_signing_key, pkcs8_verification_key) = load_pkcs8_keys();

        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";

        roundtrip_sign_verify::<super::Signer, super::Verifier, _>(
            data,
            pkcs8_signing_key.as_ref(),
            pkcs8_verification_key.as_ref(),
        )?;
        Ok(())
    }
}
