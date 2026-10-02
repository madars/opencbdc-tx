/* Copyright (c) 2024 MIT Digital Currency Initiative,
 *                    Federal Reserve Bank of Boston
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Helpers built alongside the vendored pq-crystals/dilithium reference
 * implementation (FIPS 204 ML-DSA), using its internal headers:
 *
 *  - mldsa_pk_from_sk: FIPS 204's packed secret key omits t1, so the public key
 *    is not a prefix of it; recompute it (FIPS 204, Algorithm 6).
 *
 *  - mldsa_ctx_init/mldsa_ctx_sign: the reference recomputes the key-derived
 *    matrix A and the NTTs of s1/s2/t0 on every signature. A sentinel signs
 *    many transactions under one key, so cache those once and reuse them. The
 *    signing loop mirrors ref/sign.c's crypto_sign_signature_internal exactly,
 *    with the cached values substituted in.
 */

#include <stdint.h>
#include <string.h>

#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"

void mldsa_pk_from_sk(uint8_t *pk, const uint8_t *sk) {
    uint8_t rho[SEEDBYTES];
    uint8_t tr[TRBYTES];
    uint8_t key[SEEDBYTES];
    polyvecl mat[K];
    polyvecl s1;
    polyvecl s1hat;
    polyveck s2;
    polyveck t1;
    polyveck t0;

    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    polyvec_matrix_expand(mat, rho);

    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);
    polyveck_add(&t1, &t1, &s2);
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);

    pack_pk(pk, rho, &t1);
}

typedef struct {
    polyvecl mat[K];
    polyvecl s1hat;
    polyveck s2hat;
    polyveck t0hat;
    uint8_t tr[TRBYTES];
    uint8_t key[SEEDBYTES];
} mldsa_ctx;

size_t mldsa_ctx_size(void) {
    return sizeof(mldsa_ctx);
}

void mldsa_ctx_init(uint8_t *ctxbuf, const uint8_t *sk) {
    mldsa_ctx *ctx = (mldsa_ctx *)ctxbuf;
    uint8_t rho[SEEDBYTES];
    polyvecl s1;
    polyveck t0;
    polyveck s2;

    unpack_sk(rho, ctx->tr, ctx->key, &t0, &s1, &s2, sk);

    polyvec_matrix_expand(ctx->mat, rho);

    ctx->s1hat = s1;
    polyvecl_ntt(&ctx->s1hat);
    ctx->s2hat = s2;
    polyveck_ntt(&ctx->s2hat);
    ctx->t0hat = t0;
    polyveck_ntt(&ctx->t0hat);
}

int mldsa_ctx_sign(uint8_t *sig,
                   size_t *siglen,
                   const uint8_t *m,
                   size_t mlen,
                   const uint8_t *ctxbuf) {
    const mldsa_ctx *ctx = (const mldsa_ctx *)ctxbuf;
    const uint8_t pre[2] = {0, 0}; /* FIPS 204 empty context */
    uint8_t mu[CRHBYTES];
    uint8_t rhoprime[CRHBYTES];
    uint8_t rnd[RNDBYTES];
    uint16_t nonce = 0;
    unsigned int n;
    polyvecl y;
    polyvecl z;
    polyveck w1;
    polyveck w0;
    polyveck h;
    poly cp;
    keccak_state state;

    randombytes(rnd, RNDBYTES);

    /* mu = CRH(tr, pre, m) */
    shake256_init(&state);
    shake256_absorb(&state, ctx->tr, TRBYTES);
    shake256_absorb(&state, pre, sizeof(pre));
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(mu, CRHBYTES, &state);

    /* rhoprime = CRH(key, rnd, mu) */
    shake256_init(&state);
    shake256_absorb(&state, ctx->key, SEEDBYTES);
    shake256_absorb(&state, rnd, RNDBYTES);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_finalize(&state);
    shake256_squeeze(rhoprime, CRHBYTES, &state);

rej:
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    z = y;
    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, ctx->mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(sig, &w1);

    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(sig, CTILDEBYTES, &state);
    poly_challenge(&cp, sig);
    poly_ntt(&cp);

    polyvecl_pointwise_poly_montgomery(&z, &cp, &ctx->s1hat);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
    if(polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    polyveck_pointwise_poly_montgomery(&h, &cp, &ctx->s2hat);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &w0, &h);
    polyveck_reduce(&w0);
    if(polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    polyveck_pointwise_poly_montgomery(&h, &cp, &ctx->t0hat);
    polyveck_invntt_tomont(&h);
    polyveck_reduce(&h);
    if(polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    polyveck_add(&w0, &w0, &h);
    n = polyveck_make_hint(&h, &w0, &w1);
    if(n > OMEGA) {
        goto rej;
    }

    pack_sig(sig, sig, &z, &h);
    *siglen = CRYPTO_BYTES;
    return 0;
}
