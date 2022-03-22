/*
 *  Function signatures for functionality that can be provided by
 *  cryptographic accelerators.
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_DRIVER_WRAPPERS_H
#define PSA_CRYPTO_DRIVER_WRAPPERS_H

#include "psa/crypto.h"
#include "psa/crypto_driver_common.h"

/*
 * Initialization and termination functions
 */
psa_status_t psa_driver_wrapper_init( void );
void psa_driver_wrapper_free( void );

/*
 * Signature functions
 */
psa_status_t psa_driver_wrapper_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *signature,
    xalSize_t signature_size,
    xalSize_t *signature_length );

psa_status_t psa_driver_wrapper_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    const uint8_t *signature,
    xalSize_t signature_length );

psa_status_t psa_driver_wrapper_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, xalSize_t hash_length,
    uint8_t *signature, xalSize_t signature_size, xalSize_t *signature_length );

psa_status_t psa_driver_wrapper_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, xalSize_t hash_length,
    const uint8_t *signature, xalSize_t signature_length );

/*
 * Key handling functions
 */

psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, xalSize_t data_length,
    uint8_t *key_buffer, xalSize_t key_buffer_size,
    xalSize_t *key_buffer_length, xalSize_t *bits );

psa_status_t psa_driver_wrapper_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    uint8_t *data, xalSize_t data_size, xalSize_t *data_length );

psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    uint8_t *data, xalSize_t data_size, xalSize_t *data_length );

psa_status_t psa_driver_wrapper_get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    xalSize_t *key_buffer_size );

psa_status_t psa_driver_wrapper_get_key_buffer_size_from_key_data(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    xalSize_t data_length,
    xalSize_t *key_buffer_size );

psa_status_t psa_driver_wrapper_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, xalSize_t key_buffer_size, xalSize_t *key_buffer_length );

psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, xalSize_t key_buffer_size, xalSize_t *key_buffer_length );

psa_status_t psa_driver_wrapper_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, xalSize_t source_key_length,
    uint8_t *target_key_buffer, xalSize_t target_key_buffer_size,
    xalSize_t *target_key_buffer_length );
/*
 * Cipher functions
 */
psa_status_t psa_driver_wrapper_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    xalSize_t iv_length,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_cipher_set_iv(
    psa_cipher_operation_t *operation,
    const uint8_t *iv,
    xalSize_t iv_length );

psa_status_t psa_driver_wrapper_cipher_update(
    psa_cipher_operation_t *operation,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_cipher_finish(
    psa_cipher_operation_t *operation,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_cipher_abort(
    psa_cipher_operation_t *operation );

/*
 * Hashing functions
 */
psa_status_t psa_driver_wrapper_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *hash,
    xalSize_t hash_size,
    xalSize_t *hash_length);

psa_status_t psa_driver_wrapper_hash_setup(
    psa_hash_operation_t *operation,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_hash_clone(
    const psa_hash_operation_t *source_operation,
    psa_hash_operation_t *target_operation );

psa_status_t psa_driver_wrapper_hash_update(
    psa_hash_operation_t *operation,
    const uint8_t *input,
    xalSize_t input_length );

psa_status_t psa_driver_wrapper_hash_finish(
    psa_hash_operation_t *operation,
    uint8_t *hash,
    xalSize_t hash_size,
    xalSize_t *hash_length );

psa_status_t psa_driver_wrapper_hash_abort(
    psa_hash_operation_t *operation );

/*
 * AEAD functions
 */

psa_status_t psa_driver_wrapper_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, xalSize_t nonce_length,
    const uint8_t *additional_data, xalSize_t additional_data_length,
    const uint8_t *plaintext, xalSize_t plaintext_length,
    uint8_t *ciphertext, xalSize_t ciphertext_size, xalSize_t *ciphertext_length );

psa_status_t psa_driver_wrapper_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, xalSize_t nonce_length,
    const uint8_t *additional_data, xalSize_t additional_data_length,
    const uint8_t *ciphertext, xalSize_t ciphertext_length,
    uint8_t *plaintext, xalSize_t plaintext_size, xalSize_t *plaintext_length );

psa_status_t psa_driver_get_tag_len(
    psa_aead_operation_t *operation,
    uint8_t *tag_len );

psa_status_t psa_driver_wrapper_aead_encrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_aead_decrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_aead_set_nonce(
    psa_aead_operation_t *operation,
    const uint8_t *nonce,
    xalSize_t nonce_length );

psa_status_t psa_driver_wrapper_aead_set_lengths(
    psa_aead_operation_t *operation,
    xalSize_t ad_length,
    xalSize_t plaintext_length );

psa_status_t psa_driver_wrapper_aead_update_ad(
    psa_aead_operation_t *operation,
    const uint8_t *input,
    xalSize_t input_length );

psa_status_t psa_driver_wrapper_aead_update(
    psa_aead_operation_t *operation,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_aead_finish(
    psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    xalSize_t ciphertext_size,
    xalSize_t *ciphertext_length,
    uint8_t *tag,
    xalSize_t tag_size,
    xalSize_t *tag_length );

psa_status_t psa_driver_wrapper_aead_verify(
    psa_aead_operation_t *operation,
    uint8_t *plaintext,
    xalSize_t plaintext_size,
    xalSize_t *plaintext_length,
    const uint8_t *tag,
    xalSize_t tag_length );

psa_status_t psa_driver_wrapper_aead_abort(
    psa_aead_operation_t *operation );

/*
 * MAC functions
 */
psa_status_t psa_driver_wrapper_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    uint8_t *mac,
    xalSize_t mac_size,
    xalSize_t *mac_length );

psa_status_t psa_driver_wrapper_mac_sign_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_mac_verify_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg );

psa_status_t psa_driver_wrapper_mac_update(
    psa_mac_operation_t *operation,
    const uint8_t *input,
    xalSize_t input_length );

psa_status_t psa_driver_wrapper_mac_sign_finish(
    psa_mac_operation_t *operation,
    uint8_t *mac,
    xalSize_t mac_size,
    xalSize_t *mac_length );

psa_status_t psa_driver_wrapper_mac_verify_finish(
    psa_mac_operation_t *operation,
    const uint8_t *mac,
    xalSize_t mac_length );

psa_status_t psa_driver_wrapper_mac_abort(
    psa_mac_operation_t *operation );

/*
 * Asymmetric cryptography
 */
psa_status_t psa_driver_wrapper_asymmetric_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    const uint8_t *salt,
    xalSize_t salt_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

psa_status_t psa_driver_wrapper_asymmetric_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    xalSize_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    xalSize_t input_length,
    const uint8_t *salt,
    xalSize_t salt_length,
    uint8_t *output,
    xalSize_t output_size,
    xalSize_t *output_length );

#endif /* PSA_CRYPTO_DRIVER_WRAPPERS_H */

/* End of automatically generated file. */
