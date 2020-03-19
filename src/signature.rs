#[cfg(feature = "signing-ring")]
pub use crate::crypto::ring::{Signer as SignerRing, Verifier as VerifierRing};
#[cfg(feature = "signing-shrapnel")]
pub use crate::crypto::shrapnel::{Signer as SignerShrapnel, Verifier as VerifierShrapnel};

#[cfg(any(test, feature = "signing-shrapnel", feature = "signing-ring"))]
pub(crate) mod test {

    use crate::crypto::{Algorithm, LoaderPkcs8, Signing, Verifying, RSA_SHA256};
    use crate::errors::RPMError;
    // use ::pem;

    pub(crate) fn roundtrip_sign_verify<S, V, A>(
        data: &[u8],
        pkcs8_signing_key: &[u8],
        pkcs8_verification_key: &[u8],
    ) -> Result<(), RPMError>
    where
        S: Signing<A, Signature = Vec<u8>> + LoaderPkcs8,
        V: Verifying<A, Signature = Vec<u8>> + LoaderPkcs8,
        A: Algorithm,
    {
        let signature = {
            let signer = S::load_from_pkcs8(pkcs8_signing_key)?;
            signer.sign(data)?
        };

        let verifier = V::load_from_pkcs8(pkcs8_verification_key).unwrap();
        verifier.verify(data, &signature)?;

        Ok(())
    }

    pub(crate) fn load_pkcs8_keys() -> (Vec<u8>, Vec<u8>) {
        let pkcs8_signing_key = include_bytes!("../test_assets/rsa-2048-private-key.pkcs8");
        let pkcs8_verification_key = include_bytes!("../test_assets/public_key.der");
        (pkcs8_signing_key.to_vec(), pkcs8_verification_key.to_vec())
    }

    #[test]
    fn sign_verify_round() -> Result<(), Box<dyn std::error::Error>> {
        let (pkcs8_signing_key, pkcs8_verification_key) = load_pkcs8_keys();

        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";

        #[cfg(all(feature = "signing-shrapnel", feature = "signing-ring"))]
        roundtrip_sign_verify::<super::SignerRing, super::VerifierShrapnel, _>(
            data,
            pkcs8_signing_key.as_ref(),
            pkcs8_verification_key.as_ref(),
        )?;

        #[cfg(all(feature = "signing-shrapnel", feature = "signing-ring"))]
        roundtrip_sign_verify::<super::SignerShrapnel, super::VerifierRing, _>(
            data,
            pkcs8_signing_key.as_ref(),
            pkcs8_verification_key.as_ref(),
        )?;

        Ok(())
    }
}
