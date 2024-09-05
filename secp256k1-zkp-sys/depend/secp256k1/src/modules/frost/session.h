/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_SESSION_H
#define SECP256K1_MODULE_FROST_SESSION_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "../../scalar.h"

typedef struct {
    int fin_nonce_parity;
    unsigned char fin_nonce[32];
    rustsecp256k1zkp_v0_10_0_scalar noncecoef;
    rustsecp256k1zkp_v0_10_0_scalar challenge;
    rustsecp256k1zkp_v0_10_0_scalar s_part;
} rustsecp256k1zkp_v0_10_0_frost_session_internal;

static int rustsecp256k1zkp_v0_10_0_frost_session_load(const rustsecp256k1zkp_v0_10_0_context* ctx, rustsecp256k1zkp_v0_10_0_frost_session_internal *session_i, const rustsecp256k1zkp_v0_10_0_frost_session *session);

#endif
