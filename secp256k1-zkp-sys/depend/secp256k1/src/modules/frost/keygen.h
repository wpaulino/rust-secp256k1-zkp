/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_H
#define SECP256K1_MODULE_FROST_KEYGEN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    rustsecp256k1zkp_v0_10_0_ge pk;
    /* tweak is identical to value tacc[v] in the specification. */
    rustsecp256k1zkp_v0_10_0_scalar tweak;
    /* parity_acc corresponds to gacc[v] in the spec. If gacc[v] is -1,
     * parity_acc is 1. Otherwise, parity_acc is 0. */
    int parity_acc;
} rustsecp256k1zkp_v0_10_0_keygen_cache_internal;

static int rustsecp256k1zkp_v0_10_0_keygen_cache_load(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_keygen_cache_internal *cache_i, const rustsecp256k1zkp_v0_10_0_frost_keygen_cache *cache);

static int rustsecp256k1zkp_v0_10_0_frost_share_load(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_scalar *s, const rustsecp256k1zkp_v0_10_0_frost_share* share);

static int rustsecp256k1zkp_v0_10_0_frost_compute_indexhash(rustsecp256k1zkp_v0_10_0_scalar *indexhash, const unsigned char *id33);

static int rustsecp256k1zkp_v0_10_0_frost_lagrange_coefficient(rustsecp256k1zkp_v0_10_0_scalar *r, const unsigned char * const *ids33, size_t n_participants, const unsigned char *my_id33);

#endif
