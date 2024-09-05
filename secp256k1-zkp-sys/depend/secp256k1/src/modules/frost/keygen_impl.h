/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_IMPL_H
#define SECP256K1_MODULE_FROST_KEYGEN_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "keygen.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"

static const unsigned char rustsecp256k1zkp_v0_10_0_frost_keygen_cache_magic[4] = { 0x40, 0x25, 0x2e, 0x41 };

/* A tweak cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate (and potentially tweaked) public key
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity. */
static void rustsecp256k1zkp_v0_10_0_keygen_cache_save(rustsecp256k1zkp_v0_10_0_frost_keygen_cache *cache, rustsecp256k1zkp_v0_10_0_keygen_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, rustsecp256k1zkp_v0_10_0_frost_keygen_cache_magic, 4);
    ptr += 4;
    rustsecp256k1zkp_v0_10_0_ge_to_bytes(ptr, &cache_i->pk);
    ptr += 64;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    rustsecp256k1zkp_v0_10_0_scalar_get_b32(ptr, &cache_i->tweak);
}

static int rustsecp256k1zkp_v0_10_0_keygen_cache_load(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_keygen_cache_internal *cache_i, const rustsecp256k1zkp_v0_10_0_frost_keygen_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_memcmp_var(ptr, rustsecp256k1zkp_v0_10_0_frost_keygen_cache_magic, 4) == 0);
    ptr += 4;
    rustsecp256k1zkp_v0_10_0_ge_from_bytes(&cache_i->pk, ptr);
    ptr += 64;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Computes indexhash = tagged_hash(pk) */
static int rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(rustsecp256k1zkp_v0_10_0_scalar *indexhash, const unsigned char *id33) {
    rustsecp256k1zkp_v0_10_0_sha256 sha;
    unsigned char buf[32];

    rustsecp256k1zkp_v0_10_0_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/index", sizeof("FROST/index") - 1);
    rustsecp256k1zkp_v0_10_0_sha256_write(&sha, id33, 33);
    rustsecp256k1zkp_v0_10_0_sha256_finalize(&sha, buf);
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(indexhash, buf, NULL);
    /* The x-coordinate must not be zero (see
     * draft-irtf-cfrg-frost-08#section-4.2.2) */
    if (rustsecp256k1zkp_v0_10_0_scalar_is_zero(indexhash)) {
        return 0;
    }

    return 1;
}

static const unsigned char rustsecp256k1zkp_v0_10_0_frost_share_magic[4] = { 0xa1, 0x6a, 0x42, 0x03 };

static void rustsecp256k1zkp_v0_10_0_frost_share_save(rustsecp256k1zkp_v0_10_0_frost_share* share, rustsecp256k1zkp_v0_10_0_scalar *s) {
    memcpy(&share->data[0], rustsecp256k1zkp_v0_10_0_frost_share_magic, 4);
    rustsecp256k1zkp_v0_10_0_scalar_get_b32(&share->data[4], s);
}

static int rustsecp256k1zkp_v0_10_0_frost_share_load(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_scalar *s, const rustsecp256k1zkp_v0_10_0_frost_share* share) {
    int overflow;

    /* The magic is non-secret so it can be declassified to allow branching. */
    rustsecp256k1zkp_v0_10_0_declassify(ctx, &share->data[0], 4);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_memcmp_var(&share->data[0], rustsecp256k1zkp_v0_10_0_frost_share_magic, 4) == 0);
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(s, &share->data[4], &overflow);
    /* Parsed shares cannot overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

int rustsecp256k1zkp_v0_10_0_frost_share_serialize(const rustsecp256k1zkp_v0_10_0_context* ctx, unsigned char *out32, const rustsecp256k1zkp_v0_10_0_frost_share* share) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(share != NULL);
    memcpy(out32, &share->data[4], 32);
    return 1;
}

int rustsecp256k1zkp_v0_10_0_frost_share_parse(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_frost_share* share, const unsigned char *in32) {
    rustsecp256k1zkp_v0_10_0_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(in32 != NULL);

    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_frost_share_save(share, &tmp);
    return 1;
}

static void rustsecp256k1zkp_v0_10_0_frost_derive_coeff(rustsecp256k1zkp_v0_10_0_scalar *coeff, const unsigned char *polygen32, size_t i) {
    rustsecp256k1zkp_v0_10_0_sha256 sha;
    unsigned char buf[32];

    rustsecp256k1zkp_v0_10_0_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/coeffgen", sizeof("FROST/coeffgen") - 1);
    rustsecp256k1zkp_v0_10_0_sha256_write(&sha, polygen32, 32);
    rustsecp256k1zkp_v0_10_0_write_be64(&buf[0], i);
    rustsecp256k1zkp_v0_10_0_sha256_write(&sha, buf, 8);
    rustsecp256k1zkp_v0_10_0_sha256_finalize(&sha, buf);
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(coeff, buf, NULL);
}

static int rustsecp256k1zkp_v0_10_0_frost_vss_gen(const rustsecp256k1zkp_v0_10_0_context *ctx, rustsecp256k1zkp_v0_10_0_pubkey *vss_commitment, unsigned char *pok64, const unsigned char *polygen32, size_t threshold) {
    rustsecp256k1zkp_v0_10_0_sha256 sha;
    unsigned char buf[32];
    rustsecp256k1zkp_v0_10_0_keypair keypair;
    rustsecp256k1zkp_v0_10_0_gej rj;
    rustsecp256k1zkp_v0_10_0_ge rp;
    size_t i;
    int ret = 1;

    for (i = 0; i < threshold; i++) {
        rustsecp256k1zkp_v0_10_0_scalar coeff_i;

        rustsecp256k1zkp_v0_10_0_frost_derive_coeff(&coeff_i, polygen32, i);
        /* Compute proof-of-knowledge for constant term */
        if (i == threshold - 1) {
            rustsecp256k1zkp_v0_10_0_scalar_get_b32(buf, &coeff_i);
            ret &= rustsecp256k1zkp_v0_10_0_keypair_create(ctx, &keypair, buf);

            rustsecp256k1zkp_v0_10_0_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/KeygenPoK", sizeof("FROST/KeygenPoK") - 1);
            rustsecp256k1zkp_v0_10_0_sha256_finalize(&sha, buf);

            ret &= rustsecp256k1zkp_v0_10_0_schnorrsig_sign32(ctx, pok64, buf, &keypair, NULL);
        }

        /* Compute commitment to each coefficient */
        rustsecp256k1zkp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &coeff_i);
        rustsecp256k1zkp_v0_10_0_ge_set_gej(&rp, &rj);
        rustsecp256k1zkp_v0_10_0_pubkey_save(&vss_commitment[threshold - i - 1], &rp);
    }
    return ret;
}

static int rustsecp256k1zkp_v0_10_0_frost_share_gen(rustsecp256k1zkp_v0_10_0_frost_share *share, const unsigned char *polygen32, size_t threshold, const unsigned char *id33) {
    rustsecp256k1zkp_v0_10_0_scalar idx;
    rustsecp256k1zkp_v0_10_0_scalar share_i;
    size_t i;
    int ret = 1;

    /* Derive share */
    /* See RFC 9591, appendix C.1 */
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&share_i, 0);
    if (!rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(&idx, id33)) {
        return 0;
    }
    for (i = 0; i < threshold; i++) {
        rustsecp256k1zkp_v0_10_0_scalar coeff_i;

        rustsecp256k1zkp_v0_10_0_frost_derive_coeff(&coeff_i, polygen32, i);
        /* Horner's method to evaluate polynomial to derive shares */
        rustsecp256k1zkp_v0_10_0_scalar_add(&share_i, &share_i, &coeff_i);
        if (i < threshold - 1) {
            rustsecp256k1zkp_v0_10_0_scalar_mul(&share_i, &share_i, &idx);
        }
    }
    rustsecp256k1zkp_v0_10_0_frost_share_save(share, &share_i);

    return ret;
}

int rustsecp256k1zkp_v0_10_0_frost_shares_gen(const rustsecp256k1zkp_v0_10_0_context *ctx, rustsecp256k1zkp_v0_10_0_frost_share *shares, rustsecp256k1zkp_v0_10_0_pubkey *vss_commitment, unsigned char *pok64, const unsigned char *seed32, size_t threshold, size_t n_participants, const unsigned char * const* ids33) {
    rustsecp256k1zkp_v0_10_0_sha256 sha;
    unsigned char polygen[32];
    size_t i;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shares != NULL);
    for (i = 0; i < n_participants; i++) {
        memset(&shares[i], 0, sizeof(shares[i]));
    }
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(pok64 != NULL);
    ARG_CHECK(seed32 != NULL);
    ARG_CHECK(ids33 != NULL);
    ARG_CHECK(threshold > 1);
    ARG_CHECK(n_participants >= threshold);

    /* Commit to all inputs */
    rustsecp256k1zkp_v0_10_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_10_0_sha256_write(&sha, seed32, 32);
    rustsecp256k1zkp_v0_10_0_write_be64(&polygen[0], threshold);
    rustsecp256k1zkp_v0_10_0_write_be64(&polygen[8], n_participants);
    rustsecp256k1zkp_v0_10_0_sha256_write(&sha, polygen, 16);
    for (i = 0; i < n_participants; i++) {
        rustsecp256k1zkp_v0_10_0_sha256_write(&sha, ids33[i], 33);
    }
    rustsecp256k1zkp_v0_10_0_sha256_finalize(&sha, polygen);

    ret &= rustsecp256k1zkp_v0_10_0_frost_vss_gen(ctx, vss_commitment, pok64, polygen, threshold);

    for (i = 0; i < n_participants; i++) {
        ret &= rustsecp256k1zkp_v0_10_0_frost_share_gen(&shares[i], polygen, threshold, ids33[i]);
    }

    return ret;
}

typedef struct {
    const rustsecp256k1zkp_v0_10_0_context *ctx;
    rustsecp256k1zkp_v0_10_0_scalar idx;
    rustsecp256k1zkp_v0_10_0_scalar idxn;
    const rustsecp256k1zkp_v0_10_0_pubkey *vss_commitment;
} rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_data;

typedef struct {
    const rustsecp256k1zkp_v0_10_0_context *ctx;
    rustsecp256k1zkp_v0_10_0_scalar idx;
    rustsecp256k1zkp_v0_10_0_scalar idxn;
    const rustsecp256k1zkp_v0_10_0_pubkey * const* vss_commitments;
    size_t threshold;
} rustsecp256k1zkp_v0_10_0_frost_compute_pubshare_ecmult_data;

typedef struct {
    const rustsecp256k1zkp_v0_10_0_context *ctx;
    const rustsecp256k1zkp_v0_10_0_pubkey * const* pubshares;
    const unsigned char * const *ids33;
    size_t n_pubshares;
} rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_data;

typedef struct {
    const rustsecp256k1zkp_v0_10_0_context *ctx;
    size_t idxn;
    const rustsecp256k1zkp_v0_10_0_pubkey * const* vss_commitments;
} rustsecp256k1zkp_v0_10_0_frost_vss_agg_ecmult_data;

static int rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_callback(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *data) {
    rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_data *ctx = (rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_data *) data;
    if (!rustsecp256k1zkp_v0_10_0_pubkey_load(ctx->ctx, pt, &ctx->vss_commitment[idx])) {
        return 0;
    }
    *sc = ctx->idxn;
    rustsecp256k1zkp_v0_10_0_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int rustsecp256k1zkp_v0_10_0_frost_compute_pubshare_ecmult_callback(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *data) {
    rustsecp256k1zkp_v0_10_0_frost_compute_pubshare_ecmult_data *ctx = (rustsecp256k1zkp_v0_10_0_frost_compute_pubshare_ecmult_data *) data;

    if (!rustsecp256k1zkp_v0_10_0_pubkey_load(ctx->ctx, pt, &ctx->vss_commitments[idx/ctx->threshold][idx % ctx->threshold])) {
        return 0;
    }
    if (idx != 0 && idx % ctx->threshold == 0) {
        rustsecp256k1zkp_v0_10_0_scalar_set_int(&ctx->idxn, 1);
    }
    *sc = ctx->idxn;
    rustsecp256k1zkp_v0_10_0_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_callback(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *data) {
    rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_data *ctx = (rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_data *) data;
    rustsecp256k1zkp_v0_10_0_scalar l;

    if (!rustsecp256k1zkp_v0_10_0_pubkey_load(ctx->ctx, pt, ctx->pubshares[idx])) {
        return 0;
    }

    if (!rustsecp256k1zkp_v0_10_0_frost_lagrange_coefficient(&l, ctx->ids33, ctx->n_pubshares, ctx->ids33[idx])) {
        return 0;
    }

    *sc = l;

    return 1;
}

static int rustsecp256k1zkp_v0_10_0_frost_vss_agg_pubkey_ecmult_callback(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *data) {
    rustsecp256k1zkp_v0_10_0_frost_vss_agg_ecmult_data *ctx = (rustsecp256k1zkp_v0_10_0_frost_vss_agg_ecmult_data *) data;

    if (!rustsecp256k1zkp_v0_10_0_pubkey_load(ctx->ctx, pt, &ctx->vss_commitments[idx][ctx->idxn])) {
        return 0;
    }

    *sc = rustsecp256k1zkp_v0_10_0_scalar_one;

    return 1;
}

/* See RFC 9591 */
static int rustsecp256k1zkp_v0_10_0_frost_vss_verify_internal(const rustsecp256k1zkp_v0_10_0_context* ctx, size_t threshold, const unsigned char *id33, const rustsecp256k1zkp_v0_10_0_scalar *share, const rustsecp256k1zkp_v0_10_0_pubkey *vss_commitment) {
    rustsecp256k1zkp_v0_10_0_scalar share_neg;
    rustsecp256k1zkp_v0_10_0_gej tmpj, snj;
    rustsecp256k1zkp_v0_10_0_ge sng;
    rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_data verify_share_ecmult_data;

    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    /* Use an EC multi-multiplication to verify the following equation:
     *   0 = - share_i*G + idx^0*vss_commitment[0]
     *                   + ...
     *                   + idx^(threshold - 1)*vss_commitment[threshold - 1]*/
    verify_share_ecmult_data.ctx = ctx;
    verify_share_ecmult_data.vss_commitment = vss_commitment;
    /* Evaluate the public polynomial at the idx */
    if (!rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(&verify_share_ecmult_data.idx, id33)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&verify_share_ecmult_data.idxn, 1);
    /* TODO: add scratch */
    if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, NULL, &tmpj, NULL, rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_callback, (void *) &verify_share_ecmult_data, threshold)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_scalar_negate(&share_neg, share);
    rustsecp256k1zkp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &snj, &share_neg);
    rustsecp256k1zkp_v0_10_0_ge_set_gej(&sng, &snj);
    rustsecp256k1zkp_v0_10_0_gej_add_ge(&tmpj, &tmpj, &sng);
    return rustsecp256k1zkp_v0_10_0_gej_is_infinity(&tmpj);
}

int rustsecp256k1zkp_v0_10_0_frost_share_verify(const rustsecp256k1zkp_v0_10_0_context* ctx, size_t threshold, const unsigned char *id33, const rustsecp256k1zkp_v0_10_0_frost_share *share, const rustsecp256k1zkp_v0_10_0_pubkey *vss_commitment) {
    rustsecp256k1zkp_v0_10_0_scalar share_i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(id33 != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(vss_commitment != NULL);
    ARG_CHECK(threshold > 1);

    if (!rustsecp256k1zkp_v0_10_0_frost_share_load(ctx, &share_i, share)) {
        return 0;
    }

    return rustsecp256k1zkp_v0_10_0_frost_vss_verify_internal(ctx, threshold, id33, &share_i, vss_commitment);
}

int rustsecp256k1zkp_v0_10_0_frost_compute_pubshare(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *pubshare, size_t threshold, const unsigned char *id33, const rustsecp256k1zkp_v0_10_0_pubkey *agg_vss_commitment, size_t n_participants) {
    rustsecp256k1zkp_v0_10_0_gej tmpj;
    rustsecp256k1zkp_v0_10_0_ge tmp;
    rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_data verify_share_ecmult_data;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pubshare != NULL);
    memset(pubshare, 0, sizeof(*pubshare));
    ARG_CHECK(id33 != NULL);
    ARG_CHECK(agg_vss_commitment != NULL);
    ARG_CHECK(n_participants > 1);
    ARG_CHECK(threshold > 1);

    if (threshold > n_participants) {
        return 0;
    }

    /* Use an EC multi-multiplication to verify the following equation:
     *   agg_share_i * G = idx^0*agg_vss_commitment[0]
     *                   + ...
     *                   + idx^(threshold - 1)*agg_vss_commitment[threshold - 1]*/
    verify_share_ecmult_data.ctx = ctx;
    verify_share_ecmult_data.vss_commitment = agg_vss_commitment;
    /* Evaluate the public polynomial at the idx */
    if (!rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(&verify_share_ecmult_data.idx, id33)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&verify_share_ecmult_data.idxn, 1);
    /* TODO: add scratch */
    if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, NULL, &tmpj, NULL, rustsecp256k1zkp_v0_10_0_frost_verify_share_ecmult_callback, (void *) &verify_share_ecmult_data, threshold)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_ge_set_gej(&tmp, &tmpj);
    rustsecp256k1zkp_v0_10_0_pubkey_save(pubshare, &tmp);

    return 1;
}

static int rustsecp256k1zkp_v0_10_0_frost_vss_agg(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *agg_vss_commitment, const rustsecp256k1zkp_v0_10_0_pubkey * const *vss_commitments, size_t n_participants, size_t threshold) {
    rustsecp256k1zkp_v0_10_0_gej tmpj;
    rustsecp256k1zkp_v0_10_0_ge tmp;
    rustsecp256k1zkp_v0_10_0_frost_vss_agg_ecmult_data vss_agg_ecmult_data;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(agg_vss_commitment != NULL);
    ARG_CHECK(vss_commitments != NULL);
    ARG_CHECK(n_participants > 1);
    ARG_CHECK(threshold > 1);

    vss_agg_ecmult_data.ctx = ctx;
    vss_agg_ecmult_data.vss_commitments = vss_commitments;

    for (vss_agg_ecmult_data.idxn = 0; vss_agg_ecmult_data.idxn < threshold; vss_agg_ecmult_data.idxn++) {
        /* TODO: add scratch */
        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, NULL, &tmpj, NULL, rustsecp256k1zkp_v0_10_0_frost_vss_agg_pubkey_ecmult_callback, (void *) &vss_agg_ecmult_data, n_participants)) {
            return 0;
        }
        rustsecp256k1zkp_v0_10_0_ge_set_gej(&tmp, &tmpj);
        rustsecp256k1zkp_v0_10_0_pubkey_save(&agg_vss_commitment[vss_agg_ecmult_data.idxn], &tmp);
    }

    return 1;
}

int rustsecp256k1zkp_v0_10_0_frost_share_agg(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_frost_share *agg_share, rustsecp256k1zkp_v0_10_0_pubkey *agg_vss_commitment, const rustsecp256k1zkp_v0_10_0_frost_share * const* shares, const rustsecp256k1zkp_v0_10_0_pubkey * const* vss_commitments, const unsigned char * const *pok64s, size_t n_shares, size_t threshold, const unsigned char *id33) {
    rustsecp256k1zkp_v0_10_0_scalar acc;
    size_t i;
    int ret = 1;
    rustsecp256k1zkp_v0_10_0_sha256 sha;
    unsigned char buf[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_share != NULL);
    memset(agg_share, 0, sizeof(*agg_share));
    ARG_CHECK(shares != NULL);
    ARG_CHECK(pok64s != NULL);
    ARG_CHECK(vss_commitments != NULL);
    ARG_CHECK(id33 != NULL);
    ARG_CHECK(n_shares > 1);
    ARG_CHECK(threshold > 1);

    if (threshold > n_shares) {
        return 0;
    }

    /* Verify proofs-of-knowledge */
    rustsecp256k1zkp_v0_10_0_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/KeygenPoK", sizeof("FROST/KeygenPoK") - 1);
    rustsecp256k1zkp_v0_10_0_sha256_finalize(&sha, buf);
    for (i = 0; i < n_shares; i++) {
        rustsecp256k1zkp_v0_10_0_xonly_pubkey pk;

        if (!rustsecp256k1zkp_v0_10_0_xonly_pubkey_from_pubkey(ctx, &pk, NULL, &vss_commitments[i][0])) {
            return 0;
        }
        if (!rustsecp256k1zkp_v0_10_0_schnorrsig_verify(ctx, pok64s[i], buf, 32, &pk)) {
            return 0;
        }
    }

    rustsecp256k1zkp_v0_10_0_scalar_set_int(&acc, 0);
    for (i = 0; i < n_shares; i++) {
        rustsecp256k1zkp_v0_10_0_scalar share_i;

        if (!rustsecp256k1zkp_v0_10_0_frost_share_load(ctx, &share_i, shares[i])) {
            return 0;
        }
        /* Verify share against commitments */
        ret &= rustsecp256k1zkp_v0_10_0_frost_vss_verify_internal(ctx, threshold, id33, &share_i, vss_commitments[i]);
        rustsecp256k1zkp_v0_10_0_scalar_add(&acc, &acc, &share_i);
    }
    rustsecp256k1zkp_v0_10_0_frost_share_save(agg_share, &acc);
    if (!rustsecp256k1zkp_v0_10_0_frost_vss_agg(ctx, agg_vss_commitment, vss_commitments, n_shares, threshold)) {
        return 0;
    }

    return ret;
}

int rustsecp256k1zkp_v0_10_0_frost_pubkey_get(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *agg_pk, const rustsecp256k1zkp_v0_10_0_frost_keygen_cache *keyagg_cache) {
    rustsecp256k1zkp_v0_10_0_keygen_cache_internal cache_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(keyagg_cache != NULL);

    if(!rustsecp256k1zkp_v0_10_0_keygen_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_pubkey_save(agg_pk, &cache_i.pk);
    return 1;
}

int rustsecp256k1zkp_v0_10_0_frost_pubkey_gen(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_frost_keygen_cache *cache, const rustsecp256k1zkp_v0_10_0_pubkey * const *pubshares, size_t n_pubshares, const unsigned char * const *ids33) {
    rustsecp256k1zkp_v0_10_0_gej pkj;
    rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_data interpolate_pubkey_ecmult_data;
    rustsecp256k1zkp_v0_10_0_keygen_cache_internal cache_i = { 0 };

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(cache != NULL);
    ARG_CHECK(pubshares != NULL);
    ARG_CHECK(ids33 != NULL);
    ARG_CHECK(n_pubshares > 1);

    interpolate_pubkey_ecmult_data.ctx = ctx;
    interpolate_pubkey_ecmult_data.pubshares = pubshares;
    interpolate_pubkey_ecmult_data.ids33 = ids33;
    interpolate_pubkey_ecmult_data.n_pubshares = n_pubshares;

    /* TODO: add scratch */
    if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, rustsecp256k1zkp_v0_10_0_frost_interpolate_pubkey_ecmult_callback, (void *) &interpolate_pubkey_ecmult_data, n_pubshares)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_ge_set_gej(&cache_i.pk, &pkj);
    rustsecp256k1zkp_v0_10_0_keygen_cache_save(cache, &cache_i);

    return 1;
}

static int rustsecp256k1zkp_v0_10_0_frost_pubkey_tweak_add_internal(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *output_pubkey, rustsecp256k1zkp_v0_10_0_frost_keygen_cache *keygen_cache, const unsigned char *tweak32, int xonly) {
    rustsecp256k1zkp_v0_10_0_keygen_cache_internal cache_i;
    int overflow = 0;
    rustsecp256k1zkp_v0_10_0_scalar tweak;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(keygen_cache != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!rustsecp256k1zkp_v0_10_0_keygen_cache_load(ctx, &cache_i, keygen_cache)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }
    if (xonly && rustsecp256k1zkp_v0_10_0_extrakeys_ge_even_y(&cache_i.pk)) {
        cache_i.parity_acc ^= 1;
        rustsecp256k1zkp_v0_10_0_scalar_negate(&cache_i.tweak, &cache_i.tweak);
    }
    rustsecp256k1zkp_v0_10_0_scalar_add(&cache_i.tweak, &cache_i.tweak, &tweak);
    if (!rustsecp256k1zkp_v0_10_0_eckey_pubkey_tweak_add(&cache_i.pk, &tweak)) {
        return 0;
    }
    /* eckey_pubkey_tweak_add fails if cache_i.pk is infinity */
    VERIFY_CHECK(!rustsecp256k1zkp_v0_10_0_ge_is_infinity(&cache_i.pk));
    rustsecp256k1zkp_v0_10_0_keygen_cache_save(keygen_cache, &cache_i);
    if (output_pubkey != NULL) {
        rustsecp256k1zkp_v0_10_0_pubkey_save(output_pubkey, &cache_i.pk);
    }
    return 1;
}

int rustsecp256k1zkp_v0_10_0_frost_pubkey_ec_tweak_add(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *output_pubkey, rustsecp256k1zkp_v0_10_0_frost_keygen_cache *keygen_cache, const unsigned char *tweak32) {
    return rustsecp256k1zkp_v0_10_0_frost_pubkey_tweak_add_internal(ctx, output_pubkey, keygen_cache, tweak32, 0);
}

int rustsecp256k1zkp_v0_10_0_frost_pubkey_xonly_tweak_add(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_pubkey *output_pubkey, rustsecp256k1zkp_v0_10_0_frost_keygen_cache *keygen_cache, const unsigned char *tweak32) {
    return rustsecp256k1zkp_v0_10_0_frost_pubkey_tweak_add_internal(ctx, output_pubkey, keygen_cache, tweak32, 1);
}

static int rustsecp256k1zkp_v0_10_0_frost_lagrange_coefficient(rustsecp256k1zkp_v0_10_0_scalar *r, const unsigned char * const *ids33, size_t n_participants, const unsigned char *my_id33) {
    size_t i;
    rustsecp256k1zkp_v0_10_0_scalar num;
    rustsecp256k1zkp_v0_10_0_scalar den;
    rustsecp256k1zkp_v0_10_0_scalar party_idx;

    rustsecp256k1zkp_v0_10_0_scalar_set_int(&num, 1);
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&den, 1);
    if (!rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(&party_idx, my_id33)) {
        return 0;
    }
    for (i = 0; i < n_participants; i++) {
        rustsecp256k1zkp_v0_10_0_scalar mul;

        if (!rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(&mul, ids33[i])) {
            return 0;
        }
        if (rustsecp256k1zkp_v0_10_0_scalar_eq(&mul, &party_idx)) {
            continue;
        }

        rustsecp256k1zkp_v0_10_0_scalar_negate(&mul, &mul);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&num, &num, &mul);
        rustsecp256k1zkp_v0_10_0_scalar_add(&mul, &mul, &party_idx);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&den, &den, &mul);
    }

    rustsecp256k1zkp_v0_10_0_scalar_inverse_var(&den, &den);
    rustsecp256k1zkp_v0_10_0_scalar_mul(r, &num, &den);

    return 1;
}

#endif
