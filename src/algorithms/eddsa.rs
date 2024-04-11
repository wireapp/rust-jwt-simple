use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use digest::Digest;
use ed25519_dalek::{pkcs8::spki::der::pem::LineEnding, Signer};
use k256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{de::DeserializeOwned, Serialize};
use spki::{der::Encode, DecodePublicKey, EncodePublicKey};
use std::convert::TryFrom;

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Edwards25519PublicKey(ed25519_dalek::VerifyingKey);

impl AsRef<ed25519_dalek::VerifyingKey> for Edwards25519PublicKey {
    fn as_ref(&self) -> &ed25519_dalek::VerifyingKey {
        &self.0
    }
}

impl Edwards25519PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let ed25519_pk = ed25519_dalek::VerifyingKey::try_from(raw);
        Ok(Edwards25519PublicKey(
            ed25519_pk.map_err(|_| JWTError::InvalidPublicKey)?,
        ))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let ed25519_pk = ed25519_dalek::VerifyingKey::from_public_key_der(der);
        Ok(Edwards25519PublicKey(
            ed25519_pk.map_err(|_| JWTError::InvalidPublicKey)?,
        ))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let ed25519_pk = ed25519_dalek::VerifyingKey::from_public_key_pem(pem);
        Ok(Edwards25519PublicKey(
            ed25519_pk.map_err(|_| JWTError::InvalidPublicKey)?,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_public_key_der().unwrap().to_der().unwrap()
    }

    pub fn to_pem(&self) -> String {
        self.0.to_public_key_pem(LineEnding::LF).unwrap()
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct Edwards25519KeyPair {
    ed25519_kp: ed25519_dalek::SigningKey,
    metadata: Option<KeyMetadata>,
}

impl AsRef<ed25519_dalek::SigningKey> for Edwards25519KeyPair {
    fn as_ref(&self) -> &ed25519_dalek::SigningKey {
        &self.ed25519_kp
    }
}

impl Edwards25519KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let ed25519_kp = match ed25519_dalek::SigningKey::try_from(raw) {
            Ok(kp) => kp,
            Err(_) => {
                let mut kp = zeroize::Zeroizing::new([0u8; 64]);
                let len = std::cmp::min(raw.len(), 64);
                kp.copy_from_slice(&raw[..len]);
                ed25519_dalek::SigningKey::from_keypair_bytes(&kp)?
            }
        };
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let ed25519_kp = ed25519_dalek::SigningKey::from_pkcs8_der(der)?;
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let ed25519_kp = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)?;
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.ed25519_kp.to_bytes().to_vec()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.ed25519_kp.to_pkcs8_der().unwrap().to_bytes().to_vec()
    }

    pub fn to_pem(&self) -> String {
        self.ed25519_kp
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    pub fn public_key(&self) -> Edwards25519PublicKey {
        let ed25519_pk = self.ed25519_kp.verifying_key();
        Edwards25519PublicKey(ed25519_pk)
    }

    pub fn generate() -> Self {
        let ed25519_kp = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        }
    }
}

pub trait EdDSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &Edwards25519KeyPair;
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
            let signature = self.key_pair().ed25519_kp.sign(authenticated.as_bytes());

            Ok(signature.to_vec())
        })
    }
}

pub trait EdDSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &Edwards25519PublicKey;
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
                let ed25519_signature = ed25519_dalek::Signature::from_slice(signature)?;
                self.public_key()
                    .as_ref()
                    .verify_strict(authenticated.as_bytes(), &ed25519_signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &[u8],
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ed25519_signature = ed25519_dalek::Signature::from_slice(signature)?;
                self.public_key()
                    .as_ref()
                    .verify_strict(authenticated.as_bytes(), &ed25519_signature)
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

#[derive(Clone)]
pub struct Ed25519KeyPair {
    key_pair: Edwards25519KeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    pk: Edwards25519PublicKey,
    key_id: Option<String>,
}

impl EdDSAKeyPairLike for Ed25519KeyPair {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    fn key_pair(&self) -> &Edwards25519KeyPair {
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

impl Ed25519KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl EdDSAPublicKeyLike for Ed25519PublicKey {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    fn public_key(&self) -> &Edwards25519PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(sha1::Sha1::digest(&self.pk.to_der())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(sha2::Sha256::digest(&self.pk.to_der())).unwrap()
    }
}
