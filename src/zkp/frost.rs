// TODO:
// - Verify unreachables are valid.
// - Add VssCommitment type once we can obtain it from the secp256k1 API.
#![allow(missing_docs)]

#[cfg(feature = "serde")]
use crate::serde_util;
use crate::{
    ffi::{self, CPtr},
    from_hex, schnorr, Message, Parity, PublicKey, Scalar, Secp256k1, Signing, Verification,
    XOnlyPublicKey,
};
use core::{fmt, str};
#[cfg(feature = "actual-rand")]
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum FrostError {
    InvalidShare,
    InvalidPublicNonce,
    InvalidSecretNonce,
    InvalidThreshold,
    InvalidCommitment,
    InvalidProofOfKnowledge,
    InvalidPartialSignature,
}

impl fmt::Display for FrostError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let str = match *self {
            FrostError::InvalidShare => "invalid share",
            FrostError::InvalidPublicNonce => "invalid public nonce",
            FrostError::InvalidSecretNonce => "invalid secret nonce",
            FrostError::InvalidThreshold => "invalid threshold",
            FrostError::InvalidCommitment => "invalid commitment",
            FrostError::InvalidProofOfKnowledge => "invalid proof of knowledge",
            FrostError::InvalidPartialSignature => "invalid partial signature",
        };

        f.write_str(str)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FrostSecretNonce(ffi::FrostSecretNonce);

impl CPtr for FrostSecretNonce {
    type Target = ffi::FrostSecretNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FrostPublicNonce(ffi::FrostPublicNonce);

impl CPtr for FrostPublicNonce {
    type Target = ffi::FrostPublicNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl FrostPublicNonce {
    pub fn serialize(&self) -> [u8; ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE] {
        let mut nonce_bytes = [0; ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE];
        let ret = unsafe {
            ffi::secp256k1_frost_pubnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                nonce_bytes.as_mut_ptr(),
                self.as_c_ptr(),
            )
        };
        if ret == 1 {
            nonce_bytes
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, FrostError> {
        if data.len() != ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE {
            return Err(FrostError::InvalidPublicNonce);
        }

        let ret;
        let nonce = unsafe {
            let mut nonce = ffi::FrostPublicNonce::new();
            ret = ffi::secp256k1_frost_pubnonce_parse(
                ffi::secp256k1_context_no_precomp,
                &mut nonce as *mut ffi::FrostPublicNonce,
                data.as_ptr(),
            );
            nonce
        };

        if ret == 1 {
            Ok(FrostPublicNonce(nonce))
        } else {
            Err(FrostError::InvalidPublicNonce)
        }
    }
}

impl fmt::LowerHex for FrostPublicNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for FrostPublicNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for FrostPublicNonce {
    type Err = FrostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0; ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE) => {
                Self::from_slice(&res[0..ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE])
            }
            _ => Err(FrostError::InvalidPublicNonce),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FrostPublicNonce {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FrostPublicNonce {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new(
                "a hex string representing 66 byte FrostPublicNonce",
            ))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "raw 66 bytes FrostPublicNonce",
                Self::from_slice,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoefficientCommitment(Vec<ffi::PublicKey>);

impl CoefficientCommitment {
    pub fn from_public_keys(keys: Vec<PublicKey>) -> Self {
        // We own the memory so deferencing the pointer will always be safe.
        CoefficientCommitment(
            keys.into_iter()
                .map(|key| unsafe { *key.as_c_ptr() })
                .collect(),
        )
    }

    pub fn to_public_keys(&self) -> Vec<PublicKey> {
        self.0.iter().map(|key| PublicKey::from(*key)).collect()
    }
}

impl CPtr for CoefficientCommitment {
    type Target = ffi::PublicKey;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.0.as_c_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.0.as_mut_c_ptr()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationShare(PublicKey);

impl VerificationShare {
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        vss_commitment: &CoefficientCommitment,
        participant_id: &PublicKey,
        participants: usize,
    ) -> Result<Self, FrostError> {
        if vss_commitment.0.len() < 2 || vss_commitment.0.len() > participants {
            return Err(FrostError::InvalidThreshold);
        }

        let ret;
        let verification_share = unsafe {
            let mut verification_share = ffi::PublicKey::new();
            ret = ffi::secp256k1_frost_compute_pubshare(
                secp.ctx().as_ptr(),
                &mut verification_share as *mut ffi::PublicKey,
                vss_commitment.0.len(),
                participant_id.serialize().as_c_ptr(),
                vss_commitment.as_c_ptr(),
                participants,
            );
            verification_share
        };

        if ret == 1 {
            Ok(Self(PublicKey::from(verification_share)))
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn from_public_key(public_key: PublicKey) -> Self {
        Self(public_key)
    }

    pub fn as_public_key<'a>(&'a self) -> &'a PublicKey {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrostPublicKey(ffi::FrostKeygenCache);

impl CPtr for FrostPublicKey {
    type Target = ffi::FrostKeygenCache;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl FrostPublicKey {
    pub fn from_verification_shares<C: Verification>(
        secp: &Secp256k1<C>,
        verification_shares: &[&VerificationShare],
        participants: &[&PublicKey],
    ) -> Self {
        // We need an intermediate allocation to hold the serialized public keys such that we have
        // valid memory to reference.
        let participants: Vec<_> = participants
            .into_iter()
            .map(|participant| participant.serialize())
            .collect();
        let participant_ids: Vec<_> = participants.iter().map(|id| id.as_ptr()).collect();

        let ret;
        let keygen_cache = unsafe {
            let mut keygen_cache = ffi::FrostKeygenCache::new();
            ret = ffi::secp256k1_frost_pubkey_gen(
                secp.ctx().as_ptr(),
                &mut keygen_cache as *mut ffi::FrostKeygenCache,
                verification_shares.as_ptr() as *const *const ffi::PublicKey,
                verification_shares.len(),
                participant_ids.as_c_ptr(),
            );
            keygen_cache
        };

        if ret == 1 {
            Self(keygen_cache)
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn public_key<C: Verification>(&self, secp: &Secp256k1<C>) -> PublicKey {
        let ret;
        let pubkey = unsafe {
            let mut pubkey = ffi::PublicKey::new();
            ret = ffi::secp256k1_frost_pubkey_get(
                secp.ctx().as_ptr(),
                &mut pubkey as *mut ffi::PublicKey,
                self.as_c_ptr(),
            );
            pubkey
        };

        if ret == 1 {
            PublicKey::from(pubkey)
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn add_tweak<C: Verification>(&mut self, secp: &Secp256k1<C>, tweak: Scalar) {
        let ret = unsafe {
            ffi::secp256k1_frost_pubkey_ec_tweak_add(
                secp.ctx().as_ptr(),
                core::ptr::null_mut(),
                self.as_mut_c_ptr(),
                tweak.to_be_bytes().as_c_ptr(),
            )
        };
        if ret != 1 {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn add_x_only_tweak<C: Verification>(&mut self, secp: &Secp256k1<C>, tweak: Scalar) {
        let ret = unsafe {
            ffi::secp256k1_frost_pubkey_xonly_tweak_add(
                secp.ctx().as_ptr(),
                core::ptr::null_mut(),
                self.as_mut_c_ptr(),
                tweak.to_be_bytes().as_c_ptr(),
            )
        };
        if ret != 1 {
            unreachable!("Arguments must be valid and well-typed")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrostShare(ffi::FrostShare);

impl CPtr for FrostShare {
    type Target = ffi::FrostShare;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl fmt::LowerHex for FrostShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for FrostShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for FrostShare {
    type Err = FrostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0; ffi::FROST_SHARE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(ffi::FROST_SHARE_SERIALIZED_SIZE) => {
                Self::from_slice(&res[0..ffi::FROST_SHARE_SERIALIZED_SIZE])
            }
            _ => Err(FrostError::InvalidShare),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FrostShare {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FrostShare {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte FrostShare",
            ))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "raw 32 bytes FrostShare",
                Self::from_slice,
            ))
        }
    }
}

impl FrostShare {
    pub fn serialize(&self) -> [u8; ffi::FROST_SHARE_SERIALIZED_SIZE] {
        let mut share_bytes = [0; ffi::FROST_SHARE_SERIALIZED_SIZE];
        let ret = unsafe {
            ffi::secp256k1_frost_share_serialize(
                ffi::secp256k1_context_no_precomp,
                share_bytes.as_mut_ptr(),
                self.as_c_ptr(),
            )
        };

        if ret == 1 {
            share_bytes
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, FrostError> {
        if data.len() != ffi::FROST_SHARE_SERIALIZED_SIZE {
            return Err(FrostError::InvalidSecretNonce);
        }

        let ret;
        let share = unsafe {
            let mut share = ffi::FrostShare::new();
            ret = ffi::secp256k1_frost_share_parse(
                ffi::secp256k1_context_no_precomp,
                &mut share as *mut ffi::FrostShare,
                data.as_ptr(),
            );
            share
        };

        if ret == 1 {
            Ok(FrostShare(share))
        } else {
            Err(FrostError::InvalidSecretNonce)
        }
    }

    pub fn aggregate<C: Verification>(
        secp: &Secp256k1<C>,
        intermediate_shares: &[&FrostShare],
        coefficient_commitments: &[&CoefficientCommitment],
        poks: &[&schnorr::Signature],
        participant_id: &PublicKey,
        threshold: usize,
    ) -> Result<(FrostShare, CoefficientCommitment), FrostError> {
        if threshold < 2
            || threshold > intermediate_shares.len()
            || threshold > coefficient_commitments.len()
        {
            return Err(FrostError::InvalidThreshold);
        }

        // We can't cast to a `*const *const ffi::PublicKey` because each `CoefficientCommitment`
        // holds its own array of `ffi::PublicKey`s.
        let coefficient_commitment_ptrs = coefficient_commitments
            .iter()
            .map(|coefficient_commitment| coefficient_commitment.as_c_ptr())
            .collect::<Vec<_>>();

        // We need an intermediate allocation to hold the serialized signatures such that we have
        // valid memory to reference.
        let poks = poks.iter().map(|pok| pok.serialize()).collect::<Vec<_>>();
        let poks = poks.iter().map(|pok| pok.as_c_ptr()).collect::<Vec<_>>();

        let ret;
        let (aggregate_share, vss_commitment) = unsafe {
            let mut aggregate_share = ffi::FrostShare::new();
            let mut vss_commitment: Vec<ffi::PublicKey> = vec![ffi::PublicKey::new(); threshold];
            ret = ffi::secp256k1_frost_share_agg(
                secp.ctx().as_ptr(),
                &mut aggregate_share as *mut ffi::FrostShare,
                vss_commitment.as_mut_ptr(),
                intermediate_shares.as_ptr() as *const *const ffi::FrostShare,
                coefficient_commitment_ptrs.as_ptr(),
                poks.as_c_ptr(),
                intermediate_shares.len(),
                threshold,
                participant_id.serialize().as_c_ptr(),
            );
            (aggregate_share, vss_commitment)
        };

        if ret == 1 {
            Ok((Self(aggregate_share), CoefficientCommitment(vss_commitment)))
        } else {
            Err(FrostError::InvalidCommitment)
        }
    }

    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        coefficient_commitment: &CoefficientCommitment,
        participant_id: &PublicKey,
        threshold: usize,
    ) -> Result<(), FrostError> {
        if threshold < 2 {
            return Err(FrostError::InvalidThreshold);
        }

        let ret = unsafe {
            ffi::secp256k1_frost_share_verify(
                secp.ctx().as_ptr(),
                threshold,
                participant_id.serialize().as_c_ptr(),
                self.as_c_ptr(),
                coefficient_commitment.as_c_ptr() as *const ffi::PublicKey,
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(FrostError::InvalidCommitment)
        }
    }
}

pub fn generate_frost_shares<C: Signing>(
    secp: &Secp256k1<C>,
    seed: &[u8; 32],
    threshold: usize,
    participants: &[&PublicKey],
) -> Result<(Vec<FrostShare>, CoefficientCommitment, schnorr::Signature), FrostError> {
    if threshold < 2 || threshold > participants.len() {
        return Err(FrostError::InvalidThreshold);
    }

    // We need an intermediate allocation to hold the serialized public keys such that we have valid
    // memory to reference.
    let participants: Vec<_> = participants
        .into_iter()
        .map(|participant| participant.serialize())
        .collect();
    let participant_ids: Vec<_> = participants.iter().map(|id| id.as_ptr()).collect();

    let mut proof_of_knowledge = [0u8; 64];

    let ret;
    let (shares, coefficient_commitment) = unsafe {
        let mut shares = vec![ffi::FrostShare::new(); participants.len()];
        let mut coefficient_commitment = vec![ffi::PublicKey::new(); threshold];
        ret = ffi::secp256k1_frost_shares_gen(
            secp.ctx().as_ptr(),
            shares.as_mut_c_ptr(),
            coefficient_commitment.as_mut_c_ptr(),
            proof_of_knowledge.as_mut_c_ptr(),
            seed.as_ptr(),
            threshold,
            participants.len(),
            participant_ids.as_ptr(),
        );
        (shares, coefficient_commitment)
    };

    if ret == 1 {
        Ok((
            shares.into_iter().map(|s| FrostShare(s)).collect(),
            CoefficientCommitment(coefficient_commitment),
            schnorr::Signature::from_slice(&proof_of_knowledge)
                .expect("Proof of knowledge must be valid"),
        ))
    } else {
        unreachable!("Arguments must be valid and well-typed")
    }
}

pub struct FrostSessionId([u8; 32]);

impl FrostSessionId {
    #[cfg(feature = "rand-std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand-std")))]
    pub fn random() -> Self {
        Self::new(&mut rand::thread_rng())
    }

    #[cfg(feature = "actual-rand")]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        Self(session_id)
    }

    /// Obtains the inner bytes of the [`FrostSessionId`].
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Obtains a reference to the inner bytes of the [`FrostSessionId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn new_frost_nonce_pair<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    session_id: FrostSessionId,
    aggregate_share: &FrostShare,
    frost_pubkey: &FrostPublicKey,
    msg: &Message,
    extra_rand: Option<[u8; 32]>,
) -> (FrostSecretNonce, FrostPublicNonce) {
    let ret;
    let (secret_nonce, public_nonce) = unsafe {
        let mut secret_nonce = ffi::FrostSecretNonce::new();
        let mut public_nonce = ffi::FrostPublicNonce::new();
        ret = ffi::secp256k1_frost_nonce_gen(
            secp.ctx().as_ptr(),
            &mut secret_nonce as *mut ffi::FrostSecretNonce,
            &mut public_nonce as *mut ffi::FrostPublicNonce,
            session_id.as_bytes().as_c_ptr(),
            aggregate_share.as_c_ptr(),
            msg.as_c_ptr(),
            frost_pubkey.as_c_ptr(),
            extra_rand.as_c_ptr(),
        );
        (secret_nonce, public_nonce)
    };

    if ret == 1 {
        (
            FrostSecretNonce(secret_nonce),
            FrostPublicNonce(public_nonce),
        )
    } else {
        unreachable!("Arguments must be valid and well-typed")
    }
}

pub fn adapt(
    pre_signature: schnorr::Signature,
    secret_adaptor: Scalar,
    nonce_parity: Parity,
) -> schnorr::Signature {
    let mut signature = [0u8; 64];
    let ret = unsafe {
        ffi::secp256k1_frost_adapt(
            ffi::secp256k1_context_no_precomp,
            signature.as_mut_c_ptr(),
            pre_signature.as_c_ptr(),
            secret_adaptor.to_be_bytes().as_c_ptr(),
            nonce_parity.into(),
        )
    };

    if ret == 1 {
        schnorr::Signature::from_slice(&signature).expect("Signature must be valid")
    } else {
        unreachable!("Arguments must be valid and well-typed")
    }
}

pub fn extract_adaptor(
    signature: schnorr::Signature,
    pre_signature: schnorr::Signature,
    nonce_parity: Parity,
) -> Scalar {
    let mut secret = Scalar::ZERO.to_be_bytes();
    let ret = unsafe {
        ffi::secp256k1_frost_extract_adaptor(
            ffi::secp256k1_context_no_precomp,
            secret.as_mut_c_ptr(),
            signature.as_c_ptr(),
            pre_signature.as_c_ptr(),
            nonce_parity.into(),
        )
    };

    if ret == 1 {
        Scalar::from_be_bytes(secret).expect("Secret must be a valid scalar")
    } else {
        unreachable!("Arguments must be valid and well-typed")
    }
}

pub fn verify_adaptor(
    pre_signature: schnorr::Signature,
    message: Message,
    pubkey: XOnlyPublicKey,
    adaptor: PublicKey,
    nonce_parity: Parity,
) -> bool {
    let ret = unsafe {
        ffi::secp256k1_frost_verify_adaptor(
            ffi::secp256k1_context_no_precomp,
            pre_signature.as_c_ptr(),
            message.as_c_ptr(),
            pubkey.as_c_ptr(),
            adaptor.as_c_ptr(),
            nonce_parity.into(),
        )
    };
    ret == 1
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FrostPartialSignature(ffi::FrostPartialSignature);

impl CPtr for FrostPartialSignature {
    type Target = ffi::FrostPartialSignature;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl FrostPartialSignature {
    pub fn serialize(&self) -> [u8; ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE] {
        let mut sig_bytes = [0; ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE];
        let ret = unsafe {
            ffi::secp256k1_frost_partial_sig_serialize(
                ffi::secp256k1_context_no_precomp,
                sig_bytes.as_mut_ptr(),
                self.as_c_ptr(),
            )
        };

        if ret == 1 {
            sig_bytes
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, FrostError> {
        if data.len() != ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE {
            return Err(FrostError::InvalidPartialSignature);
        }

        let ret;
        let partial_sig = unsafe {
            let mut partial_sig = FrostPartialSignature(ffi::FrostPartialSignature::new());
            ret = ffi::secp256k1_frost_partial_sig_parse(
                ffi::secp256k1_context_no_precomp,
                partial_sig.as_mut_c_ptr(),
                data.as_ptr(),
            );
            partial_sig
        };

        if ret == 1 {
            Ok(partial_sig)
        } else {
            Err(FrostError::InvalidPartialSignature)
        }
    }
}

impl fmt::LowerHex for FrostPartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for FrostPartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for FrostPartialSignature {
    type Err = FrostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0; ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE) => {
                Self::from_slice(&res[0..ffi::FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE])
            }
            _ => Err(FrostError::InvalidPartialSignature),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FrostPartialSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FrostPartialSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte FrostPartialSignature",
            ))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "raw 32 bytes FrostPartialSignature",
                Self::from_slice,
            ))
        }
    }
}

#[derive(Debug)]
pub struct FrostSession(ffi::FrostSession);

impl CPtr for FrostSession {
    type Target = ffi::FrostSession;

    fn as_c_ptr(&self) -> *const Self::Target {
        &self.0
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        &mut self.0
    }
}

impl FrostSession {
    pub fn new<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        nonces: &[&FrostPublicNonce],
        msg: &Message,
        frost_pubkey: &FrostPublicKey,
        participant_id: &PublicKey,
        participants: &[&PublicKey],
        adaptor: Option<PublicKey>,
    ) -> Self {
        // We need an intermediate allocation to hold the serialized public keys such that we have
        // valid memory to reference.
        let participants: Vec<_> = participants
            .into_iter()
            .map(|participant| participant.serialize())
            .collect();
        let participant_ids: Vec<_> = participants.iter().map(|id| id.as_ptr()).collect();

        let ret;
        let session = unsafe {
            let mut session = ffi::FrostSession::new();
            ret = ffi::secp256k1_frost_nonce_process(
                secp.ctx().as_ptr(),
                &mut session as *mut ffi::FrostSession,
                nonces.as_ptr() as *const *const ffi::FrostPublicNonce,
                nonces.len(),
                msg.as_c_ptr(),
                participant_id.serialize().as_c_ptr(),
                participant_ids.as_c_ptr(),
                frost_pubkey.as_c_ptr(),
                adaptor.as_c_ptr(),
            );
            session
        };

        if ret == 1 {
            FrostSession(session)
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        mut nonce: FrostSecretNonce,
        aggregate_share: &FrostShare,
        aggregate_pubkey: &FrostPublicKey,
    ) -> FrostPartialSignature {
        let ret;
        let partial_sig = unsafe {
            let mut partial_sig = ffi::FrostPartialSignature::new();
            ret = ffi::secp256k1_frost_partial_sign(
                secp.ctx().as_ptr(),
                &mut partial_sig as *mut ffi::FrostPartialSignature,
                nonce.as_mut_c_ptr(),
                aggregate_share.as_c_ptr(),
                self.as_c_ptr(),
                aggregate_pubkey.as_c_ptr(),
            );
            partial_sig
        };

        if ret == 1 {
            FrostPartialSignature(partial_sig)
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn verify_partial_sig<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sig: &FrostPartialSignature,
        nonce: &FrostPublicNonce,
        verification_share: &VerificationShare,
        aggregate_pubkey: &FrostPublicKey,
    ) -> Result<(), FrostError> {
        let ret = unsafe {
            ffi::secp256k1_frost_partial_sig_verify(
                secp.ctx().as_ptr(),
                partial_sig.as_c_ptr(),
                nonce.as_c_ptr(),
                verification_share.0.as_c_ptr(),
                self.as_c_ptr(),
                aggregate_pubkey.as_c_ptr(),
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(FrostError::InvalidPartialSignature)
        }
    }

    pub fn aggregate_partial_sigs<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sigs: &[&FrostPartialSignature],
    ) -> schnorr::Signature {
        let mut schnorr_sig = [0u8; 64];
        let ret = unsafe {
            ffi::secp256k1_frost_partial_sig_agg(
                secp.ctx().as_ptr(),
                schnorr_sig.as_mut_c_ptr(),
                self.as_c_ptr(),
                partial_sigs.as_ptr() as *const *const ffi::FrostPartialSignature,
                partial_sigs.len(),
            )
        };

        if ret == 1 {
            schnorr::Signature::from_slice(&schnorr_sig).expect("Signature must be valid")
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }

    pub fn nonce_parity(&self) -> Parity {
        let mut parity = core::ffi::c_int::default();
        let ret = unsafe {
            ffi::secp256k1_frost_nonce_parity(
                ffi::secp256k1_context_no_precomp,
                &mut parity,
                self.as_c_ptr(),
            )
        };

        if ret == 1 {
            Parity::from_i32(parity).expect("Parity guaranteed to be binary")
        } else {
            unreachable!("Arguments must be valid and well-typed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::SecretKey;
    #[cfg(feature = "global-context")]
    use rand::{seq::SliceRandom, thread_rng, RngCore};

    #[test]
    fn test_pubnonce_round_trip() {
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &seckey);
        let mut nonce = [0u8; ffi::FROST_PUBLIC_NONCE_SERIALIZED_SIZE];
        nonce[..33].copy_from_slice(&pubkey.serialize());
        nonce[33..].copy_from_slice(&pubkey.serialize());
        assert_eq!(
            FrostPublicNonce::from_slice(&nonce).unwrap().serialize(),
            nonce
        );
    }

    #[test]
    fn test_share_round_trip() {
        let share = [1u8; ffi::FROST_SHARE_SERIALIZED_SIZE];
        assert_eq!(FrostShare::from_slice(&share).unwrap().serialize(), share);
    }

    #[cfg(feature = "global-context")]
    #[derive(Debug)]
    struct Participant {
        id: PublicKey,
        shares: Vec<FrostShare>,
        coefficient_commitment: CoefficientCommitment,
        proof_of_knowledge: Option<schnorr::Signature>,
        aggregate_share: Option<FrostShare>,
        vss_commitment: CoefficientCommitment,
        verification_share: Option<VerificationShare>,
    }

    #[cfg(feature = "global-context")]
    #[derive(Debug)]
    struct SigningParticipant<'a> {
        participant: &'a Participant,
        secret_nonce: Option<FrostSecretNonce>,
        public_nonce: FrostPublicNonce,
        session: Option<FrostSession>,
        partial_sig: Option<FrostPartialSignature>,
    }

    #[cfg(feature = "global-context")]
    #[test]
    fn test_sign_with_tweak() {
        const THRESHOLD: usize = 2;
        const NUM_PARTICIPANTS: usize = 2;

        let secp = Secp256k1::new();
        let mut participants = Vec::with_capacity(NUM_PARTICIPANTS);
        let mut participant_ids = Vec::with_capacity(NUM_PARTICIPANTS);
        for _ in 0..NUM_PARTICIPANTS {
            let mut secret_key = [0; 32];
            thread_rng().fill_bytes(&mut secret_key);
            let id =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret_key).unwrap());
            participants.push(Participant {
                id,
                shares: Vec::new(),
                coefficient_commitment: CoefficientCommitment::from_public_keys(Vec::new()),
                proof_of_knowledge: None,
                aggregate_share: None,
                vss_commitment: CoefficientCommitment::from_public_keys(Vec::new()),
                verification_share: None,
            });
            participant_ids.push(id);
        }

        let mut coefficient_commitments = Vec::with_capacity(NUM_PARTICIPANTS);
        for participant in &mut participants {
            let mut seed = [0; 32];
            thread_rng().fill_bytes(&mut seed);
            let (shares, coefficient_commitment, proof_of_knowledge) = generate_frost_shares(
                &secp,
                &seed,
                THRESHOLD,
                participant_ids.iter().collect::<Vec<_>>().as_slice(),
            )
            .unwrap();
            participant.shares = shares;
            participant.coefficient_commitment = coefficient_commitment.clone();
            participant.proof_of_knowledge = Some(proof_of_knowledge);
            coefficient_commitments.push(coefficient_commitment);
        }

        for i in 0..NUM_PARTICIPANTS {
            let mut intermediate_shares = Vec::with_capacity(NUM_PARTICIPANTS);
            for j in 0..NUM_PARTICIPANTS {
                intermediate_shares.push(&participants[j].shares[i]);
            }
            for j in 0..NUM_PARTICIPANTS {
                intermediate_shares[j]
                    .verify(
                        &secp,
                        &participants[j].coefficient_commitment,
                        &participants[i].id,
                        THRESHOLD,
                    )
                    .unwrap();
            }

            let poks = participants
                .iter()
                .map(|participant| participant.proof_of_knowledge.as_ref().unwrap())
                .collect::<Vec<_>>();

            let (aggregate_share, vss_commitment) = FrostShare::aggregate(
                &secp,
                &intermediate_shares,
                &coefficient_commitments
                    .iter()
                    .collect::<Vec<_>>()
                    .as_slice(),
                &poks,
                &participants[i].id,
                THRESHOLD,
            )
            .unwrap();
            participants[i].aggregate_share = Some(aggregate_share);
            participants[i].vss_commitment = vss_commitment;

            if i > 0 {
                assert_eq!(
                    participants[i - 1].vss_commitment,
                    participants[i].vss_commitment
                );
            }

            let verification_share = VerificationShare::new(
                &secp,
                &participants[i].vss_commitment,
                &participants[i].id,
                participants.len(),
            )
            .unwrap();
            participants[i].verification_share = Some(verification_share);
        }

        let verification_shares = participants
            .iter()
            .map(|participant| participant.verification_share.as_ref().unwrap())
            .collect::<Vec<_>>();
        let mut aggregate_pubkey = FrostPublicKey::from_verification_shares(
            &secp,
            &verification_shares,
            participant_ids.iter().collect::<Vec<_>>().as_slice(),
        );
        aggregate_pubkey.add_tweak(&secp, Scalar::random());
        aggregate_pubkey.add_x_only_tweak(&secp, Scalar::random());
        let (final_pubkey, _) = aggregate_pubkey.public_key(&secp).x_only_public_key();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg[..]);
        let msg = Message::from_digest(msg);

        let mut signers = participants
            .choose_multiple(&mut thread_rng(), THRESHOLD)
            .map(|participant| {
                let (secret_nonce, public_nonce) = new_frost_nonce_pair(
                    &secp,
                    FrostSessionId::random(),
                    participant.aggregate_share.as_ref().unwrap(),
                    &aggregate_pubkey,
                    &msg,
                    None,
                );
                SigningParticipant {
                    participant,
                    secret_nonce: Some(secret_nonce),
                    public_nonce,
                    session: None,
                    partial_sig: None,
                }
            })
            .collect::<Vec<_>>();

        let public_nonces = signers
            .iter()
            .map(|signer| signer.public_nonce)
            .collect::<Vec<_>>();
        let signer_ids = signers
            .iter()
            .map(|signer| signer.participant.id)
            .collect::<Vec<_>>();
        for signer in &mut signers {
            let session = FrostSession::new(
                &secp,
                public_nonces.iter().collect::<Vec<_>>().as_slice(),
                &msg,
                &aggregate_pubkey,
                &signer.participant.id,
                signer_ids.iter().collect::<Vec<_>>().as_slice(),
                None,
            );

            let partial_sig = session.partial_sign(
                &secp,
                signer.secret_nonce.take().unwrap(),
                signer.participant.aggregate_share.as_ref().unwrap(),
                &aggregate_pubkey,
            );
            signer.session = Some(session);
            signer.partial_sig = Some(partial_sig);
        }

        let partial_sigs = signers
            .iter()
            .map(|signer| signer.partial_sig.unwrap())
            .collect::<Vec<_>>();
        let mut final_sig = None;
        for signer in &signers {
            signer
                .session
                .as_ref()
                .unwrap()
                .verify_partial_sig(
                    &secp,
                    signer.partial_sig.as_ref().unwrap(),
                    &signer.public_nonce,
                    signer.participant.verification_share.as_ref().unwrap(),
                    &aggregate_pubkey,
                )
                .unwrap();

            let aggregate_sig = signer
                .session
                .as_ref()
                .unwrap()
                .aggregate_partial_sigs(&secp, partial_sigs.iter().collect::<Vec<_>>().as_slice());

            if let Some(final_sig) = final_sig {
                assert_eq!(aggregate_sig, final_sig);
            } else {
                final_sig = Some(aggregate_sig);
            }
        }

        secp.verify_schnorr(final_sig.as_ref().unwrap(), &msg, &final_pubkey)
            .unwrap();
    }

    // Check out `frost_multi_hop_lock_tests` for adaptor test
}
