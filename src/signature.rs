#[cfg(feature = "signing-pgp")]
pub use crate::crypto::pgp::{Signer as SignerPGP, Verifier as VerifierPGP};
#[cfg(feature = "signing-ring")]
pub use crate::crypto::ring::{Signer as Signerring, Verifier as VerifierRing};

#[cfg(test)]
#[cfg(any(test, feature = "signing-pgp", feature = "signing-ring"))]
pub(crate) mod test {

    use crate::crypto::{Algorithm, KeyLoader, Signing, Verifying};
    use crate::errors::RPMError;
    // use ::pem;

    pub(crate) fn roundtrip_sign_verify<S, V, A>(
        data: &[u8],
        pkcs8_signing_key: &[u8],
        pkcs8_verification_key: &[u8],
    ) -> Result<(), RPMError>
    where
        S: Signing<A, Signature = Vec<u8>> + KeyLoader,
        V: Verifying<A, Signature = Vec<u8>> + KeyLoader,
        A: Algorithm,
    {
        let signature = {
            let signer = S::load_from(pkcs8_signing_key)?;
            signer.sign(data)?
        };

        let verifier = V::load_from(pkcs8_verification_key).unwrap();
        verifier.verify(data, &signature)?;

        Ok(())
    }

    pub(crate) fn load_der_keys() -> (Vec<u8>, Vec<u8>) {
        let pkcs8_signing_key = include_bytes!("../test_assets/id_rsa.der");
        let pkcs8_verification_key = include_bytes!("../test_assets/id_rsa.pub.der");
        (pkcs8_signing_key.to_vec(), pkcs8_verification_key.to_vec())
    }

    pub(crate) fn load_pem_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../test_assets/id_rsa.pem");
        let verification_key = include_bytes!("../test_assets/id_rsa.pub.pem");
        (signing_key.to_vec(), verification_key.to_vec())
    }

    pub(crate) fn load_asc_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../test_assets/id_rsa.asc");
        let verification_key = include_bytes!("../test_assets/id_rsa.pub.asc");
        (signing_key.to_vec(), verification_key.to_vec())
    }

    #[cfg(all(feature = "signing-pgp", feature = "signing-ring"))]
    #[test]
    fn sign_cross_verify_round() {
        let (pkcs8_signing_key, pkcs8_verification_key) = load_der_keys();

        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";

        roundtrip_sign_verify::<super::Signerring, super::VerifierPGP, _>(
            data,
            pkcs8_signing_key.as_ref(),
            pkcs8_verification_key.as_ref(),
        )
        .expect("Failed to roundtrip ring -> pgp");

        roundtrip_sign_verify::<super::SignerPGP, super::VerifierRing, _>(
            data,
            pkcs8_signing_key.as_ref(),
            pkcs8_verification_key.as_ref(),
        )
        .expect("Failed to roundtrip pgp -> ring");
    }
}
