/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_SSL_TLS13_INVASIVE_H
#define MBEDTLS_SSL_TLS13_INVASIVE_H

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_TEST_HOOKS)

#if defined(MBEDTLS_PSA_CRYPTO_C)

/**
 *  \brief  Expand the supplied \p prk into several additional pseudorandom
 *          keys, which is the output of the HKDF.
 *
 *  \param  alg       The HMAC algorithm to use (\c #PSA_ALG_HMAC( PSA_ALG_XXX )
 *                    value such that PSA_ALG_XXX is a hash algorithm and
 *                    #PSA_ALG_IS_HMAC(\p alg) is true).
 *  \param  prk       A pseudorandom key of \p prk_len bytes. \p prk is
 *                    usually the output from the HKDF extract step.
 *  \param  prk_len   The length in bytes of \p prk.
 *  \param  info      An optional context and application specific information
 *                    string. This can be a zero-length string.
 *  \param  info_len  The length of \p info in bytes.
 *  \param  okm       The output keying material of \p okm_len bytes.
 *  \param  okm_len   The length of the output keying material in bytes. This
 *                    must be less than or equal to
 *                    255 * #PSA_HASH_LENGTH( \p alg ) bytes.
 *
 *  \return 0 on success.
 *  \return #PSA_ERROR_INVALID_ARGUMENT when the parameters are invalid.
 *  \return An PSA_ERROR_* error for errors returned from the underlying
 *          PSA layer.
 */
psa_status_t mbedtls_psa_hkdf_expand( psa_algorithm_t alg,
                                      const unsigned char *prk, xalSize_t prk_len,
                                      const unsigned char *info, xalSize_t info_len,
                                      unsigned char *okm, xalSize_t okm_len );

#endif /* MBEDTLS_PSA_CRYPTO_C */

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_SSL_TLS13_INVASIVE_H */
