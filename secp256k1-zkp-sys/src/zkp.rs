use core::{
    fmt,
    hash::{self, Hash},
};
use {types::*, Context, PublicKey, Signature, XOnlyPublicKey};

/// Rangeproof maximum length
pub const RANGEPROOF_MAX_LENGTH: size_t = 5134;
pub const ECDSA_ADAPTOR_SIGNATURE_LENGTH: size_t = 162;

/// The maximum number of whitelist keys.
pub const WHITELIST_MAX_N_KEYS: size_t = 255;

extern "C" {
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_pedersen_commitment_parse"
    )]
    // Parse a 33-byte commitment into 64 byte internal commitment object
    pub fn secp256k1_pedersen_commitment_parse(
        cx: *const Context,
        commit: *mut PedersenCommitment,
        input: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_pedersen_commitment_serialize"
    )]
    // Serialize a 64-byte commit object into a 33 byte serialized byte sequence
    pub fn secp256k1_pedersen_commitment_serialize(
        cx: *const Context,
        output: *mut c_uchar,
        commit: *const PedersenCommitment,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_pedersen_commit"
    )]
    // Generates a pedersen commitment: *commit = blind * G + value * G2.
    // The commitment is 33 bytes, the blinding factor is 32 bytes.
    pub fn secp256k1_pedersen_commit(
        ctx: *const Context,
        commit: *mut PedersenCommitment,
        blind: *const c_uchar,
        value: u64,
        value_gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_pedersen_blind_generator_blind_sum"
    )]
    /// Sets the final Pedersen blinding factor correctly when the generators themselves
    ///  have blinding factors.
    ///
    /// Consider a generator of the form A' = A + rG, where A is the "real" generator
    /// but A' is the generator provided to verifiers. Then a Pedersen commitment
    /// P = vA' + r'G really has the form vA + (vr + r')G. To get all these (vr + r')
    /// to sum to zero for multiple commitments, we take three arrays consisting of
    /// the `v`s, `r`s, and `r'`s, respectively called `value`s, `generator_blind`s
    /// and `blinding_factor`s, and sum them.
    ///
    /// The function then subtracts the sum of all (vr + r') from the last element
    /// of the `blinding_factor` array, setting the total sum to zero.
    ///
    /// Returns 1: Blinding factor successfully computed.
    ///         0: Error. A blinding_factor or generator_blind are larger than the group
    ///            order (probability for random 32 byte number < 2^-127). Retry with
    ///            different values.
    ///
    /// In:                 ctx: pointer to a context object
    ///                   value: array of asset values, `v` in the above paragraph.
    ///                          May not be NULL unless `n_total` is 0.
    ///         generator_blind: array of asset blinding factors, `r` in the above paragraph
    ///                          May not be NULL unless `n_total` is 0.
    ///                 n_total: Total size of the above arrays
    ///                n_inputs: How many of the initial array elements represent commitments that
    ///                          will be negated in the final sum
    /// In/Out: blinding_factor: array of commitment blinding factors, `r'` in the above paragraph
    ///                          May not be NULL unless `n_total` is 0.
    ///                          the last value will be modified to get the total sum to zero.
    pub fn secp256k1_pedersen_blind_generator_blind_sum(
        ctx: *const Context,
        value: *const u64,
        generator_blind: *const *const c_uchar,
        blinding_factor: *const *mut c_uchar,
        n_total: size_t,
        n_inputs: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_pedersen_verify_tally"
    )]
    // Takes two list of 64-byte commitments and sums the first set and
    // subtracts the second and verifies that they sum to 0.
    pub fn secp256k1_pedersen_verify_tally(
        ctx: *const Context,
        commits: *const &PedersenCommitment,
        pcnt: size_t,
        ncommits: *const &PedersenCommitment,
        ncnt: size_t,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_rangeproof_info"
    )]
    pub fn secp256k1_rangeproof_info(
        ctx: *const Context,
        exp: *mut c_int,
        mantissa: *mut c_int,
        min_value: *mut u64,
        max_value: *mut u64,
        proof: *const c_uchar,
        plen: size_t,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_rangeproof_rewind"
    )]
    pub fn secp256k1_rangeproof_rewind(
        ctx: *const Context,
        blind_out: *mut c_uchar,
        value_out: *mut u64,
        message_out: *mut c_uchar,
        outlen: *mut size_t,
        nonce: *const c_uchar,
        min_value: *mut u64,
        max_value: *mut u64,
        commit: *const PedersenCommitment,
        proof: *const c_uchar,
        plen: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_rangeproof_verify"
    )]
    pub fn secp256k1_rangeproof_verify(
        ctx: *const Context,
        min_value: &mut u64,
        max_value: &mut u64,
        commit: *const PedersenCommitment,
        proof: *const c_uchar,
        plen: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_rangeproof_sign"
    )]
    pub fn secp256k1_rangeproof_sign(
        ctx: *const Context,
        proof: *mut c_uchar,
        plen: *mut size_t,
        min_value: u64,
        commit: *const PedersenCommitment,
        blind: *const c_uchar,
        nonce: *const c_uchar,
        exp: c_int,
        min_bits: c_int,
        value: u64,
        message: *const c_uchar,
        msg_len: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_initialize"
    )]
    pub fn secp256k1_surjectionproof_initialize(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        input_index: *mut size_t,
        fixed_input_tags: *const Tag,
        n_input_tags: size_t,
        n_input_tags_to_use: size_t,
        fixed_output_tag: *const Tag,
        n_max_iterations: size_t,
        random_seed32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_serialize"
    )]
    pub fn secp256k1_surjectionproof_serialize(
        ctx: *const Context,
        output: *mut c_uchar,
        outputlen: *mut size_t,
        proof: *const SurjectionProof,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_serialized_size"
    )]
    pub fn secp256k1_surjectionproof_serialized_size(
        ctx: *const Context,
        proof: *const SurjectionProof,
    ) -> size_t;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_parse"
    )]
    pub fn secp256k1_surjectionproof_parse(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        input_bytes: *const c_uchar,
        input_len: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_generate"
    )]
    pub fn secp256k1_surjectionproof_generate(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        ephemeral_input_tags: *const PublicKey,
        n_ephemeral_input_tags: size_t,
        ephemeral_output_tag: *const PublicKey,
        input_index: size_t,
        input_blinding_key: *const c_uchar,
        output_blinding_key: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_surjectionproof_verify"
    )]
    pub fn secp256k1_surjectionproof_verify(
        ctx: *const Context,
        proof: *const SurjectionProof,
        ephemeral_input_tags: *const PublicKey,
        n_ephemeral_input_tags: size_t,
        ephemeral_output_tag: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_generator_generate_blinded"
    )]
    pub fn secp256k1_generator_generate_blinded(
        ctx: *const Context,
        gen: *mut PublicKey,
        key32: *const c_uchar,
        blind32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_generator_serialize"
    )]
    pub fn secp256k1_generator_serialize(
        ctx: *const Context,
        output: *mut c_uchar,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_generator_parse"
    )]
    pub fn secp256k1_generator_parse(
        ctx: *const Context,
        output: *mut PublicKey,
        bytes: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_nonce_function_ecdsa_adaptor"
    )]
    pub static secp256k1_nonce_function_ecdsa_adaptor: EcdsaAdaptorNonceFn;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_ecdsa_adaptor_encrypt"
    )]
    pub fn secp256k1_ecdsa_adaptor_encrypt(
        cx: *const Context,
        adaptor_sig162: *mut EcdsaAdaptorSignature,
        seckey32: *const c_uchar,
        enckey: *const PublicKey,
        msg32: *const c_uchar,
        noncefp: EcdsaAdaptorNonceFn,
        ndata: *mut c_void,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_ecdsa_adaptor_verify"
    )]
    pub fn secp256k1_ecdsa_adaptor_verify(
        cx: *const Context,
        adaptor_sig162: *const EcdsaAdaptorSignature,
        pubkey: *const PublicKey,
        msg32: *const c_uchar,
        enckey: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_ecdsa_adaptor_decrypt"
    )]
    pub fn secp256k1_ecdsa_adaptor_decrypt(
        cx: *const Context,
        sig: *mut Signature,
        deckey32: *const c_uchar,
        adaptor_sig162: *const EcdsaAdaptorSignature,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_ecdsa_adaptor_recover"
    )]
    pub fn secp256k1_ecdsa_adaptor_recover(
        cx: *const Context,
        deckey32: *mut c_uchar,
        sig: *const Signature,
        adaptor_sig162: *const EcdsaAdaptorSignature,
        enckey: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_whitelist_signature_parse"
    )]
    pub fn secp256k1_whitelist_signature_parse(
        cx: *const Context,
        sig: *mut WhitelistSignature,
        input: *const c_uchar,
        input_len: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_whitelist_signature_serialize"
    )]
    pub fn secp256k1_whitelist_signature_serialize(
        ctx: *const Context,
        output: *mut c_uchar,
        outputlen: *mut size_t,
        sig: *const WhitelistSignature,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_whitelist_sign"
    )]
    pub fn secp256k1_whitelist_sign(
        ctx: *const Context,
        sig: *mut WhitelistSignature,
        online_keys: *const PublicKey,
        offline_keys: *const PublicKey,
        n_keys: size_t,
        sub_pubkey: *const PublicKey,
        online_seckey: *const c_uchar,
        summed_seckey: *const c_uchar,
        index: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_10_0_whitelist_verify"
    )]
    pub fn secp256k1_whitelist_verify(
        ctx: *const Context,
        sig: *const WhitelistSignature,
        online_keys: *const PublicKey,
        offline_keys: *const PublicKey,
        n_keys: size_t,
        sub_pubkey: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubnonce_parse"
    )]
    pub fn secp256k1_frost_pubnonce_parse(
        ctx: *const Context,
        nonce: *mut FrostPublicNonce,
        in66: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubnonce_serialize"
    )]
    pub fn secp256k1_frost_pubnonce_serialize(
        ctx: *const Context,
        out66: *mut c_uchar,
        nonce: *const FrostPublicNonce,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_partial_sig_parse"
    )]
    pub fn secp256k1_frost_partial_sig_parse(
        ctx: *const Context,
        frost_partial_sig: *mut FrostPartialSignature,
        in32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_partial_sig_serialize"
    )]
    pub fn secp256k1_frost_partial_sig_serialize(
        ctx: *const Context,
        out32: *mut c_uchar,
        frost_partial_sig: *const FrostPartialSignature,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_share_parse"
    )]
    pub fn secp256k1_frost_share_parse(
        ctx: *const Context,
        share: *mut FrostShare,
        in32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_share_serialize"
    )]
    pub fn secp256k1_frost_share_serialize(
        ctx: *const Context,
        out32: *mut c_uchar,
        share: *const FrostShare,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_shares_gen"
    )]
    pub fn secp256k1_frost_shares_gen(
        ctx: *const Context,
        shares: *mut FrostShare,
        vss_commitments: *mut PublicKey,
        pok64: *mut c_uchar,
        seed32: *const c_uchar,
        threshold: size_t,
        n_participants: size_t,
        ids33: *const *const c_uchar,
    ) -> c_uint;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_share_agg"
    )]
    pub fn secp256k1_frost_share_agg(
        ctx: *const Context,
        agg_share: *mut FrostShare,
		agg_vss_commitment: *mut PublicKey,
        shares: *const *const FrostShare,
        vss_commitments: *const *const PublicKey,
        pok64s: *const *const c_uchar,
        n_shares: size_t,
        threshold: size_t,
        id33: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_share_verify"
    )]
    pub fn secp256k1_frost_share_verify(
        ctx: *const Context,
        threshold: size_t,
        id33: *const c_uchar,
        share: *const FrostShare,
        vss_commitment: *const *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_compute_pubshare"
    )]
    pub fn secp256k1_frost_compute_pubshare(
        ctx: *const Context,
        pubshare: *mut PublicKey,
        threshold: size_t,
        id33: *const c_uchar,
        vss_commitments: *const *const PublicKey,
        n_participants: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubkey_gen"
    )]
    pub fn secp256k1_frost_pubkey_gen(
        ctx: *const Context,
        keygen_cache: *mut FrostKeygenCache,
        pubshares: *const *const PublicKey,
        n_pubshares: size_t,
        ids33: *const *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubkey_get"
    )]
    pub fn secp256k1_frost_pubkey_get(
        ctx: *const Context,
        pk: *mut PublicKey,
        keygen_cache: *const FrostKeygenCache,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubkey_ec_tweak_add"
    )]
    pub fn secp256k1_frost_pubkey_ec_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey, // Can be NULL
        keygen_cache: *mut FrostKeygenCache,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_pubkey_xonly_tweak_add"
    )]
    pub fn secp256k1_frost_pubkey_xonly_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey, // Can be NULL
        keygen_cache: *mut FrostKeygenCache,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_nonce_gen"
    )]
    pub fn secp256k1_frost_nonce_gen(
        ctx: *const Context,
        secnonce: *const FrostSecretNonce,
        pubnonce: *const FrostPublicNonce,
        session_id32: *const c_uchar,
        agg_share: *const FrostShare,          // Can be NULL
        msg32: *const c_uchar,                 // Can be NULL
        keygen_cache: *const FrostKeygenCache, // Can be NULL
        extra_input32: *const c_uchar,         // Can be NULL
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_nonce_process"
    )]
    pub fn secp256k1_frost_nonce_process(
        ctx: *const Context,
        session: *mut FrostSession,
        pubnonces: *const *const FrostPublicNonce,
        n_pubnonces: size_t,
        msg32: *const c_uchar,
        my_id33: *const c_uchar,
        ids33: *const *const c_uchar,
        keygen_cache: *const FrostKeygenCache,
        adaptor: *const PublicKey, // Can be NULL
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_partial_sign"
    )]
    pub fn secp256k1_frost_partial_sign(
        ctx: *const Context,
        partial_sig: *mut FrostPartialSignature,
        secnonce: *mut FrostSecretNonce,
        agg_share: *const FrostShare,
        session: *const FrostSession,
        keygen_cache: *const FrostKeygenCache,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_partial_sig_verify"
    )]
    pub fn secp256k1_frost_partial_sig_verify(
        ctx: *const Context,
        partial_sig: *const FrostPartialSignature,
        pubnonce: *const FrostPublicNonce,
        pubshare: *const PublicKey,
        session: *const FrostSession,
        keygen_cache: *const FrostKeygenCache,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_partial_sig_agg"
    )]
    pub fn secp256k1_frost_partial_sig_agg(
        ctx: *const Context,
        sig64: *mut c_uchar,
        session: *const FrostSession,
        partial_sigs: *const *const FrostPartialSignature,
        n_sigs: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_nonce_parity"
    )]
    pub fn secp256k1_frost_nonce_parity(
        ctx: *const Context,
        nonce_parity: *mut c_int,
        session: *const FrostSession,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_verify_adaptor"
    )]
    pub fn secp256k1_frost_verify_adaptor(
        ctx: *const Context,
        pre_sig64: *const c_uchar,
        msg32: *const c_uchar,
        pubkey: *const XOnlyPublicKey,
        adaptor: *const PublicKey,
        nonce_parity: c_int,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_adapt"
    )]
    pub fn secp256k1_frost_adapt(
        ctx: *const Context,
        sig64: *mut c_uchar,
        pre_sig64: *const c_uchar,
        sec_adaptor32: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_10_0_frost_extract_adaptor"
    )]
    pub fn secp256k1_frost_extract_adaptor(
        ctx: *const Context,
        sec_adaptor32: *mut c_uchar,
        sig64: *const c_uchar,
        pre_sig64: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;
}

#[repr(C)]
#[derive(Clone)]
pub struct SurjectionProof {
    #[doc = " Total number of input asset tags"]
    pub n_inputs: size_t,
    #[doc = " Bitmap of which input tags are used in the surjection proof"]
    pub used_inputs: [c_uchar; 32usize],
    #[doc = " Borromean signature: e0, scalars"]
    pub data: [c_uchar; 8224usize],
}

impl fmt::Debug for SurjectionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slice = &self.data[..];

        f.debug_struct("SurjectionProof")
            .field("n_inputs", &self.n_inputs)
            .field("used_inputs", &self.used_inputs)
            .field("data", &slice)
            .finish()
    }
}

impl PartialEq for SurjectionProof {
    fn eq(&self, other: &Self) -> bool {
        self.n_inputs == other.n_inputs
            && self.used_inputs == other.used_inputs
            && self.data[..] == other.data[..]
    }
}

impl Eq for SurjectionProof {}

impl Ord for SurjectionProof {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.n_inputs.cmp(&other.n_inputs) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.used_inputs.cmp(&other.used_inputs) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.data.cmp(&other.data)
    }
}

impl PartialOrd for SurjectionProof {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for SurjectionProof {
    fn default() -> Self {
        SurjectionProof::new()
    }
}

impl hash::Hash for SurjectionProof {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.n_inputs.hash(state);
        self.used_inputs.hash(state);
        for byte in self.data.iter() {
            byte.hash(state);
        }
    }
}

impl SurjectionProof {
    pub fn new() -> Self {
        Self {
            n_inputs: 0,
            used_inputs: [0u8; 32],
            data: [0u8; 8224],
        }
    }
}

#[cfg(feature = "std")]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RangeProof(Box<[c_uchar]>);

#[cfg(feature = "std")]
impl RangeProof {
    pub fn new(bytes: &[u8]) -> Self {
        RangeProof(bytes.into())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_ptr(&self) -> *const c_uchar {
        self.0.as_ptr()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Tag([c_uchar; 32]);
impl_array_newtype!(Tag, c_uchar, 32);
impl_raw_debug!(Tag);

impl Tag {
    pub fn new() -> Self {
        Tag([0; 32])
    }
}

impl Default for Tag {
    fn default() -> Self {
        Tag::new()
    }
}

impl From<[u8; 32]> for Tag {
    fn from(bytes: [u8; 32]) -> Self {
        Tag(bytes)
    }
}

impl From<Tag> for [u8; 32] {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

// TODO: Replace this with ffi::PublicKey?
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd)]
pub struct PedersenCommitment([c_uchar; 64]);
impl_array_newtype!(PedersenCommitment, c_uchar, 64);
impl_raw_debug!(PedersenCommitment);

impl PedersenCommitment {
    pub fn new() -> Self {
        PedersenCommitment([0; 64])
    }
}

impl Default for PedersenCommitment {
    fn default() -> Self {
        PedersenCommitment::new()
    }
}

impl PartialEq for PedersenCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for PedersenCommitment {}

impl Hash for PedersenCommitment {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A ring signature for the "whitelist" scheme.
#[repr(C)]
#[derive(Clone)]
pub struct WhitelistSignature {
    /// The number of keys.
    pub n_keys: size_t,
    /// The signature in the form of e0 + n_keys s values.
    pub data: [u8; 32 * (1 + WHITELIST_MAX_N_KEYS)],
}

impl hash::Hash for WhitelistSignature {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.n_keys.hash(state);
        self.data[..].hash(state);
    }
}

impl PartialEq for WhitelistSignature {
    fn eq(&self, other: &Self) -> bool {
        self.n_keys == other.n_keys && self.data[..] == other.data[..]
    }
}
impl Eq for WhitelistSignature {}

impl Default for WhitelistSignature {
    fn default() -> WhitelistSignature {
        WhitelistSignature {
            n_keys: 0,
            data: [0; 32 * (1 + WHITELIST_MAX_N_KEYS)],
        }
    }
}

/// Same as secp256k1_nonce_function_hardened with the exception of using the
/// compressed 33-byte encoding for the pubkey argument.
pub type EcdsaAdaptorNonceFn = Option<
    unsafe extern "C" fn(
        nonce32: *mut c_uchar,
        msg32: *const c_uchar,
        key32: *const c_uchar,
        pk33: *const c_uchar,
        algo: *const c_uchar,
        algo_len: size_t,
        data: *mut c_void,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EcdsaAdaptorSignature([u8; ECDSA_ADAPTOR_SIGNATURE_LENGTH]);
impl_array_newtype!(EcdsaAdaptorSignature, u8, ECDSA_ADAPTOR_SIGNATURE_LENGTH);
impl_raw_debug!(EcdsaAdaptorSignature);

impl Default for EcdsaAdaptorSignature {
    fn default() -> EcdsaAdaptorSignature {
        EcdsaAdaptorSignature::new()
    }
}

impl EcdsaAdaptorSignature {
    /// Create a new (zeroed) ecdsa adaptor signature usable for the FFI interface
    pub fn new() -> Self {
        EcdsaAdaptorSignature([0u8; ECDSA_ADAPTOR_SIGNATURE_LENGTH])
    }

    /// Create a new ecdsa adaptor signature usable for the FFI interface from raw bytes
    ///
    /// # Safety
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; ECDSA_ADAPTOR_SIGNATURE_LENGTH]) -> Self {
        Self(data)
    }
}

impl PartialEq for EcdsaAdaptorSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for EcdsaAdaptorSignature {}

pub const FROST_SECRET_NONCE_SIZE: usize = 68;
pub const FROST_PUBLIC_NONCE_SIZE: usize = 132;
pub const FROST_PUBLIC_NONCE_SERIALIZED_SIZE: usize = 66;
pub const FROST_PARTIAL_SIGNATURE_SIZE: usize = 36;
pub const FROST_PARTIAL_SIGNATURE_SERIALIZED_SIZE: usize = 36;
pub const FROST_SHARE_SIZE: usize = 36;
pub const FROST_SHARE_SERIALIZED_SIZE: usize = 32;
pub const FROST_KEYGEN_CACHE_SIZE: usize = 101;
pub const FROST_SESSION_SIZE: usize = 133;

macro_rules! define_array_newtype {
    ($name: ident, $size: expr) => {
        #[repr(C)]
        #[derive(Copy, Clone)]
        pub struct $name([c_uchar; $size]);
        impl_array_newtype!($name, c_uchar, $size);
        impl_raw_debug!($name);

        #[cfg(not(fuzzing))]
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                &self.0[..] == &other.0[..]
            }
        }

        #[cfg(not(fuzzing))]
        impl Eq for $name {}

        impl $name {
            pub unsafe fn new() -> Self {
                Self([0; $size])
            }
        }
    };
}

define_array_newtype!(FrostSecretNonce, FROST_SECRET_NONCE_SIZE);
define_array_newtype!(FrostPublicNonce, FROST_PUBLIC_NONCE_SIZE);
define_array_newtype!(FrostPartialSignature, FROST_PARTIAL_SIGNATURE_SIZE);
define_array_newtype!(FrostShare, FROST_SHARE_SIZE);
define_array_newtype!(FrostKeygenCache, FROST_KEYGEN_CACHE_SIZE);
define_array_newtype!(FrostSession, FROST_SESSION_SIZE);
