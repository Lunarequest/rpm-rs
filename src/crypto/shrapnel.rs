use crate::crypto;

use super::*;

use crate::errors::RPMError;

use num_bigint_dig;
use rsa;
use rsa_der;
use sha2;
use sha2::Digest;

#[derive(Clone, Debug)]
pub struct Signer {
    secret_key: rsa::RSAPrivateKey,
}

impl crypto::Signing<crypto::RSA_SHA256> for Signer {
    type Signature = Vec<u8>;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError> {
        let mut hasher = sha2::Sha256::default();
        hasher.input(data);
        let digest = hasher.result();

        let signature = self
            .secret_key
            .sign::<rsa::hash::Hashes>(rsa::PaddingScheme::PKCS1v15, None, &digest[..])
            .map_err(|_e| {
                dbg!(_e);
                RPMError::new("signing shall not fail")
            })?;

        Ok(signature)
    }
}

impl crypto::LoaderPkcs8 for Signer {
    /// load the private key for signing
    fn load_from_pkcs8(bytes: &[u8]) -> Result<Self, RPMError> {
        // let secret_key_der = pem::parse(secret_key_pem)
        //     .map_err(|_e| RPMError::new("Failed to parse secret pem key"))?;

        let (n, e, d, p, q) = rsa_der::private_key_from_der(bytes)
            .map_err(|_e| RPMError::new("Failed to parse secret inner der formatted key"))?;
        let secret_key = rsa::RSAPrivateKey::from_components(
            num_bigint_dig::BigUint::from_bytes_be(n.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(e.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(d.as_slice()),
            vec![
                num_bigint_dig::BigUint::from_bytes_be(p.as_slice()),
                num_bigint_dig::BigUint::from_bytes_be(q.as_slice()),
            ],
        );
        Ok(Self { secret_key })
    }
}

#[derive(Clone, Debug)]
pub struct Verifier {
    public_key: rsa::RSAPublicKey,
}

impl crypto::Verifying<crypto::RSA_SHA256> for Verifier {
    type Signature = Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError> {
        let mut hasher = sha2::Sha256::default();
        hasher.input(data);
        let digest = hasher.result();

        use rsa::PublicKey;
        self.public_key
            .verify::<rsa::hash::Hashes>(rsa::PaddingScheme::PKCS1v15, None, &digest[..], signature)
            .map_err(|_e| RPMError::new("Failed to verify"))?;

        Ok(())
    }
}

impl crypto::LoaderPkcs8 for Verifier {
    fn load_from_pkcs8(bytes: &[u8]) -> Result<Self, RPMError> {
        let (n, e) = rsa_der::public_key_from_der(bytes)
            .map_err(|_e| RPMError::new("failed to parse from der"))?;
        let n = num_bigint_dig::BigUint::from_bytes_be(n.as_slice());
        let e = num_bigint_dig::BigUint::from_bytes_be(e.as_slice());
        let public_key = rsa::RSAPublicKey::new(n, e)
            .map_err(|_e| RPMError::new("failed to construct key from n and e"))?;
        Ok(Self { public_key })
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
