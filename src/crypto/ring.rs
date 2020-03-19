use crate::crypto;

use crate::errors::RPMError;

use ::ring::signature as risig;

use ::ring as ri;

use super::echo_signature;
use super::rfc4880;

#[derive(Debug)]
pub struct Signer {
    secret_signing_key: risig::RsaKeyPair,
    rng: ri::rand::SystemRandom,
}

impl crypto::Signing<crypto::RSA> for Signer {
    type Signature = Vec<u8>;

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError> {
        let mut signature = vec![0; self.secret_signing_key.public_modulus_len()];

        self.secret_signing_key
            .sign(&risig::RSA_PKCS1_SHA256, &self.rng, data, &mut signature)
            .map_err(|e| format!("Failed create signature: {}", e))?;

        let rfc4880_signature = rfc4880::raw_signature_to_rfc4880(signature.as_slice())?;

        echo_signature("sign", rfc4880_signature.as_slice());

        Ok(rfc4880_signature.into_vec())
    }
}

impl crypto::KeyLoader for Signer {
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError> {
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
    public_key_der: Vec<u8>,
}

impl crypto::Verifying<crypto::RSA> for Verifier {
    type Signature = Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError> {
        let public_key = risig::UnparsedPublicKey::new(
            &risig::RSA_PKCS1_2048_8192_SHA256,
            self.public_key_der.as_slice(),
        );
        let raw_signature = rfc4880::raw_signature_from_rfc4880(signature)?;

        echo_signature("verify", raw_signature.as_slice());

        public_key
            .verify(data, raw_signature.as_slice())
            .map_err(|e| format!("Failed to verify: {}", e))?;
        Ok(())
    }
}

impl crypto::KeyLoader for Verifier {
    /// load the private key for signing
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError> {
        // TODO not so pretty, need to validate here
        Ok(Self {
            public_key_der: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {

    use crate::crypto::{Algorithm, KeyLoader, Signing, Verifying, RSA};
    use crate::errors::RPMError;
    // use ::pem;

    use crate::signature::test::{load_der_keys, roundtrip_sign_verify};

    #[test]
    fn sign_verify_round() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verification_key) = load_der_keys();

        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";

        roundtrip_sign_verify::<super::Signer, super::Verifier, _>(
            data,
            signing_key.as_ref(),
            verification_key.as_ref(),
        )?;
        Ok(())
    }
}
