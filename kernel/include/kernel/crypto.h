/*
 * Cryptographic Services Header
 * Hardware-accelerated crypto support for CloudOS
 */

#ifndef KERNEL_CRYPTO_H
#define KERNEL_CRYPTO_H

#include "types.h"

// Cryptographic algorithm identifiers
typedef enum
{
    CRYPTO_AES_128_ECB = 1,
    CRYPTO_AES_128_CBC = 2,
    CRYPTO_AES_256_ECB = 3,
    CRYPTO_AES_256_CBC = 4,
    CRYPTO_AES_128_GCM = 5,
    CRYPTO_AES_256_GCM = 6,
    CRYPTO_SHA256 = 7,
    CRYPTO_SHA512 = 8,
    CRYPTO_RSA_2048 = 9,
    CRYPTO_RSA_4096 = 10,
    CRYPTO_ECDSA_P256 = 11,
    CRYPTO_ECDSA_P384 = 12,
    CRYPTO_HMAC_SHA256 = 13,
    CRYPTO_HMAC_SHA512 = 14
} crypto_algorithm_t;

// Key structure
typedef struct crypto_key
{
    uint32_t key_id;
    crypto_algorithm_t algorithm;
    uint8_t *key_data;
    size_t key_size;
    bool is_private;
    bool is_ephemeral;
    struct crypto_key *next;
} crypto_key_t;

// Hardware acceleration support
typedef enum
{
    CRYPTO_HW_NONE = 0,
    CRYPTO_HW_AESNI = 1,
    CRYPTO_HW_ARM_CRYPTO = 2,
    CRYPTO_HW_TRNG = 4
} crypto_hw_features_t;

// TLS/SSL session context
typedef struct tls_context
{
    uint32_t session_id;
    crypto_key_t *server_key;
    crypto_key_t *client_key;
    uint8_t master_secret[48];
    uint8_t client_random[32];
    uint8_t server_random[32];
    bool handshake_complete;
    uint16_t protocol_version;
    uint8_t cipher_suite;
    struct tls_context *next;
} tls_context_t;

// Certificate structure
typedef struct crypto_cert
{
    uint32_t cert_id;
    uint8_t *cert_data;
    size_t cert_size;
    uint8_t *public_key;
    size_t public_key_size;
    char subject[256];
    char issuer[256];
    uint64_t not_before;
    uint64_t not_after;
    bool is_ca;
    struct crypto_cert *next;
} crypto_cert_t;

// Cryptographic operation result codes
typedef enum
{
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_KEY = -1,
    CRYPTO_ERROR_INVALID_DATA = -2,
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -3,
    CRYPTO_ERROR_UNSUPPORTED_ALGORITHM = -4,
    CRYPTO_ERROR_HARDWARE_NOT_AVAILABLE = -5,
    CRYPTO_ERROR_AUTHENTICATION_FAILED = -6,
    CRYPTO_ERROR_ENCRYPTION_FAILED = -7,
    CRYPTO_ERROR_DECRYPTION_FAILED = -8,
    CRYPTO_ERROR_SIGNATURE_INVALID = -9,
    CRYPTO_ERROR_CERTIFICATE_INVALID = -10
} crypto_error_t;

// Core cryptographic functions
int crypto_init(void);
crypto_hw_features_t crypto_get_hw_support(void);

// Key management
crypto_key_t *crypto_generate_key(crypto_algorithm_t algorithm);
crypto_key_t *crypto_import_key(crypto_algorithm_t algorithm, const void *key_data, size_t key_size);
int crypto_export_key(uint32_t key_id, void *buffer, size_t *buffer_size);
int crypto_delete_key(uint32_t key_id);
crypto_key_t *crypto_find_key(uint32_t key_id);

// Symmetric encryption/decryption
int crypto_encrypt(crypto_algorithm_t algorithm, uint32_t key_id,
                   const void *plaintext, size_t plaintext_len,
                   void *ciphertext, size_t *ciphertext_len,
                   const void *iv, size_t iv_len);
int crypto_decrypt(crypto_algorithm_t algorithm, uint32_t key_id,
                   const void *ciphertext, size_t ciphertext_len,
                   void *plaintext, size_t *plaintext_len,
                   const void *iv, size_t iv_len);

// Authenticated encryption (AEAD)
int crypto_encrypt_aead(crypto_algorithm_t algorithm, uint32_t key_id,
                        const void *plaintext, size_t plaintext_len,
                        const void *aad, size_t aad_len,
                        void *ciphertext, size_t *ciphertext_len,
                        void *tag, size_t tag_len,
                        const void *iv, size_t iv_len);
int crypto_decrypt_aead(crypto_algorithm_t algorithm, uint32_t key_id,
                        const void *ciphertext, size_t ciphertext_len,
                        const void *aad, size_t aad_len,
                        const void *tag, size_t tag_len,
                        void *plaintext, size_t *plaintext_len,
                        const void *iv, size_t iv_len);

// Hash functions
int crypto_hash(crypto_algorithm_t algorithm,
                const void *data, size_t data_len,
                void *hash, size_t *hash_len);

// HMAC functions
int crypto_hmac(crypto_algorithm_t algorithm, uint32_t key_id,
                const void *data, size_t data_len,
                void *hmac, size_t *hmac_len);

// Random number generation
int crypto_random_bytes(void *buffer, size_t size);
int crypto_random_int(uint32_t *value);

// Asymmetric cryptography (RSA)
int crypto_rsa_generate_keypair(crypto_algorithm_t algorithm, uint32_t *public_key_id, uint32_t *private_key_id);
int crypto_rsa_encrypt(uint32_t public_key_id,
                       const void *plaintext, size_t plaintext_len,
                       void *ciphertext, size_t *ciphertext_len);
int crypto_rsa_decrypt(uint32_t private_key_id,
                       const void *ciphertext, size_t ciphertext_len,
                       void *plaintext, size_t *plaintext_len);
int crypto_rsa_sign(uint32_t private_key_id,
                    const void *data, size_t data_len,
                    void *signature, size_t *signature_len);
int crypto_rsa_verify(uint32_t public_key_id,
                      const void *data, size_t data_len,
                      const void *signature, size_t signature_len);

// Elliptic curve cryptography (ECC)
int crypto_ecc_generate_keypair(crypto_algorithm_t algorithm, uint32_t *public_key_id, uint32_t *private_key_id);
int crypto_ecc_sign(uint32_t private_key_id,
                    const void *data, size_t data_len,
                    void *signature, size_t *signature_len);
int crypto_ecc_verify(uint32_t public_key_id,
                      const void *data, size_t data_len,
                      const void *signature, size_t signature_len);

// TLS/SSL functions
tls_context_t *tls_create_context(void);
int tls_destroy_context(tls_context_t *ctx);
int tls_handshake(tls_context_t *ctx, const void *client_hello, size_t client_len,
                  void *server_hello, size_t *server_len);
int tls_encrypt(tls_context_t *ctx, const void *plaintext, size_t plaintext_len,
                void *ciphertext, size_t *ciphertext_len);
int tls_decrypt(tls_context_t *ctx, const void *ciphertext, size_t ciphertext_len,
                void *plaintext, size_t *plaintext_len);

// Certificate management
crypto_cert_t *crypto_load_certificate(const void *cert_data, size_t cert_size);
int crypto_verify_certificate(crypto_cert_t *cert, crypto_cert_t *ca_cert);
int crypto_verify_certificate_chain(crypto_cert_t *cert, crypto_cert_t **ca_certs, size_t num_cas);

// Hardware acceleration detection
bool crypto_has_aesni(void);
bool crypto_has_arm_crypto(void);
bool crypto_has_trng(void);

// Performance statistics
typedef struct crypto_stats
{
    uint64_t aes_encryptions;
    uint64_t aes_decryptions;
    uint64_t hash_operations;
    uint64_t rsa_operations;
    uint64_t ecc_operations;
    uint64_t tls_handshakes;
    uint64_t errors;
} crypto_stats_t;

crypto_stats_t *crypto_get_stats(void);

// Secure memory management
void *crypto_secure_alloc(size_t size);
void crypto_secure_free(void *ptr, size_t size);
void crypto_secure_clear(void *ptr, size_t size);

#endif
