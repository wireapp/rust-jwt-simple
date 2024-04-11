use digest::Digest;
use std::convert::TryFrom;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

use ecdsa::signature::{
    digest::FixedOutput,
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
};
use p521::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    NistP521, NonZeroScalar,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

type P521VerifyingKey = ecdsa::VerifyingKey<NistP521>;
type P521SigningKey = ecdsa::SigningKey<NistP521>;

#[doc(hidden)]
#[derive(Clone)]
pub struct P521PublicKey(P521VerifyingKey);

impl std::fmt::Debug for P521PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P521PublicKey")
            .field("key", &"[public key]")
            .finish()
    }
}

impl AsRef<P521VerifyingKey> for P521PublicKey {
    fn as_ref(&self) -> &P521VerifyingKey {
        &self.0
    }
}

impl P521PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p521_pk =
            P521VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P521PublicKey(p521_pk))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p521_pk =
            P521VerifyingKey::from_public_key_der(der).map_err(|_| JWTError::InvalidPublicKey)?;

        Ok(P521PublicKey(p521_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p521_pk =
            P521VerifyingKey::from_public_key_pem(pem).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P521PublicKey(p521_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .0
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let p521_pk = p521::PublicKey::from(self.0);
        Ok(p521_pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)?)
    }
}

#[doc(hidden)]
pub struct P521KeyPair {
    p521_sk: P521SigningKey,
    metadata: Option<KeyMetadata>,
}

impl AsRef<P521SigningKey> for P521KeyPair {
    fn as_ref(&self) -> &P521SigningKey {
        &self.p521_sk
    }
}

impl P521KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p521_sk = P521SigningKey::from_slice(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P521KeyPair {
            p521_sk,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p521_sk = P521SigningKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P521KeyPair {
            p521_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p521_sk = P521SigningKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P521KeyPair {
            p521_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.p521_sk.to_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let scalar = NonZeroScalar::from_repr(self.p521_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p521_sk =
            P521SigningKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p521_sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let scalar = NonZeroScalar::from_repr(self.p521_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p521_sk =
            P521SigningKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p521_sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    pub fn public_key(&self) -> P521PublicKey {
        let p521_sk = self.p521_sk.verifying_key();
        P521PublicKey(*p521_sk)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let p521_sk = P521SigningKey::random(&mut rng);
        P521KeyPair {
            p521_sk,
            metadata: None,
        }
    }
}

pub trait ECDSAP521KeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &P521KeyPair;
    fn key_id(&self) -> &Option<String>;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error>;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone());
        self.sign_with_header(Some(claims), header)
    }

    fn sign_with_header<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: Option<JWTClaims<CustomClaims>>,
        header: JWTHeader,
    ) -> Result<String, Error> {
        let jwt_header = header.with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |authenticated| {
            let mut digest = sha2::Sha512::new();
            digest.update(authenticated.as_bytes());
            let mut rng = rand::thread_rng();

            let sk = self.key_pair().as_ref().clone();
            let sk = p521::ecdsa::SigningKey::from(sk);

            let signature: p521::ecdsa::Signature =
                sk.sign_prehash_with_rng(&mut rng, &digest.finalize_fixed())?;
            Ok(signature.to_vec())
        })
    }
}

pub trait ECDSAP521PublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &P521PublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);

    fn verify_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        Token::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                let mut digest = sha2::Sha512::new();
                digest.update(authenticated.as_bytes());
                self.public_key()
                    .as_ref()
                    .verify_prehash(&digest.finalize_fixed(), &ecdsa_signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                let mut digest = sha2::Sha512::new();
                digest.update(authenticated.as_bytes());
                self.public_key()
                    .as_ref()
                    .verify_prehash(&digest.finalize_fixed(), &ecdsa_signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    fn create_key_id(&mut self) -> &str {
        self.set_key_id(
            Base64UrlSafeNoPadding::encode_to_string(sha2::Sha256::digest(
                &self.public_key().to_bytes(),
            ))
            .unwrap(),
        );
        self.key_id().as_ref().map(|x| x.as_str()).unwrap()
    }
}

pub struct ES512KeyPair {
    key_pair: P521KeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ES512PublicKey {
    pk: P521PublicKey,
    key_id: Option<String>,
}

impl ECDSAP521KeyPairLike for ES512KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES512"
    }

    fn key_pair(&self) -> &P521KeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }
}

impl ES512KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES512KeyPair {
            key_pair: P521KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES512KeyPair {
            key_pair: P521KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES512KeyPair {
            key_pair: P521KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> ES512PublicKey {
        ES512PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES512KeyPair {
            key_pair: P521KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl ECDSAP521PublicKeyLike for ES512PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES512"
    }

    fn public_key(&self) -> &P521PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES512PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES512PublicKey {
            pk: P521PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES512PublicKey {
            pk: P521PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES512PublicKey {
            pk: P521PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}
