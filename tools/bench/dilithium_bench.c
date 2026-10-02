/* Copyright (c) 2024 MIT Digital Currency Initiative,
 *                    Federal Reserve Bank of Boston
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Microbenchmark for the vendored FIPS 204 ML-DSA reference implementation.
 * Reports average keygen/sign/verify latency. Build with MLDSA_MODE to select
 * the parameter set.
 */

#include <api.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2
#endif

#if DILITHIUM_MODE == 2
#define MLD_NS(s) pqcrystals_dilithium2_ref_##s
#define MLD_PK pqcrystals_dilithium2_PUBLICKEYBYTES
#define MLD_SK pqcrystals_dilithium2_SECRETKEYBYTES
#define MLD_SIG pqcrystals_dilithium2_BYTES
#elif DILITHIUM_MODE == 3
#define MLD_NS(s) pqcrystals_dilithium3_ref_##s
#define MLD_PK pqcrystals_dilithium3_PUBLICKEYBYTES
#define MLD_SK pqcrystals_dilithium3_SECRETKEYBYTES
#define MLD_SIG pqcrystals_dilithium3_BYTES
#else
#define MLD_NS(s) pqcrystals_dilithium5_ref_##s
#define MLD_PK pqcrystals_dilithium5_PUBLICKEYBYTES
#define MLD_SK pqcrystals_dilithium5_SECRETKEYBYTES
#define MLD_SIG pqcrystals_dilithium5_BYTES
#endif

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(int argc, char **argv) {
    long iters = 2000;
    if (argc > 1) {
        iters = atol(argv[1]);
    }
    if (iters <= 0) {
        iters = 2000;
    }

    uint8_t *pk = malloc(MLD_PK);
    uint8_t *sk = malloc(MLD_SK);
    uint8_t *sig = malloc(MLD_SIG);
    uint8_t msg[32];
    memset(msg, 0x42, sizeof(msg));

    size_t siglen = 0;

    /* Warm up and sanity-check the API. */
    MLD_NS(keypair)(pk, sk);
    MLD_NS(signature)(sig, &siglen, msg, sizeof(msg), NULL, 0, sk);
    if (MLD_NS(verify)(sig, siglen, msg, sizeof(msg), NULL, 0, pk) != 0) {
        fprintf(stderr, "ML-DSA self-test failed\n");
        return 1;
    }

    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        MLD_NS(keypair)(pk, sk);
    }
    double t1 = now_ns();
    printf("keygen : %8.1f us/op\n", (t1 - t0) / (double)iters / 1e3);

    t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        MLD_NS(signature)(sig, &siglen, msg, sizeof(msg), NULL, 0, sk);
    }
    t1 = now_ns();
    printf("sign   : %8.1f us/op\n", (t1 - t0) / (double)iters / 1e3);

    t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        if (MLD_NS(verify)(sig, siglen, msg, sizeof(msg), NULL, 0, pk) != 0) {
            fprintf(stderr, "ML-DSA verify failed\n");
            return 1;
        }
    }
    t1 = now_ns();
    printf("verify : %8.1f us/op\n", (t1 - t0) / (double)iters / 1e3);

    printf("sizes  : pk=%d sk=%d sig=%d mode=%d\n",
           MLD_PK,
           MLD_SK,
           MLD_SIG,
           DILITHIUM_MODE);

    free(pk);
    free(sk);
    free(sig);
    return 0;
}
