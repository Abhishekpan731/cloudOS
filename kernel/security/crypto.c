/*
 * Cryptographic Services Implementation
 * Hardware-accelerated crypto support for CloudOS
 */

#include "kernel/crypto.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/security.h"

// Global crypto state
static crypto_key_t *crypto_keys = NULL;
static tls_context_t *tls_contexts = NULL;
static crypto_cert_t *crypto_certs = NULL;
static uint32_t next_key_id = 1;
static uint32_t next_cert_id = 1;
static crypto_hw_features_t hw_features = CRYPTO_HW_NONE;

// Performance statistics
static crypto_stats_t crypto_stats = {0};

// Simple memcpy for kernel use
static void *memcpy(void *dest, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}

// Simple memset for kernel use
static void *memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    for (size_t i = 0; i < n; i++)
    {
        p[i] = (uint8_t)c;
    }
    return s;
}

// Hardware acceleration detection
bool crypto_has_aesni(void)
{
    // Detect AES-NI support (simplified)
    return (hw_features & CRYPTO_HW_AESNI) != 0;
}

bool crypto_has_arm_crypto(void)
{
    // Detect ARM crypto extensions (simplified)
    return (hw_features & CRYPTO_HW_ARM_CRYPTO) != 0;
}

bool crypto_has_trng(void)
{
    // Detect True Random Number Generator (simplified)
    return (hw_features & CRYPTO_HW_TRNG) != 0;
}

// Initialize cryptographic services
int crypto_init(void)
{
    kprintf("Crypto: Initializing cryptographic services...\n");

    // Detect hardware acceleration
    // For now, assume no hardware acceleration is available
    hw_features = CRYPTO_HW_NONE;

    // Generate system keys for TLS
    uint32_t server_key_id, client_key_id;
    if (crypto_rsa_generate_keypair(CRYPTO_RSA_2048, &server_key_id, &client_key_id) == CRYPTO_SUCCESS)
    {
        kprintf("Crypto: Generated RSA keypair for TLS\n");
    }

    kprintf("Crypto: Initialized with hardware support: AES-NI=%s, ARM-Crypto=%s, TRNG=%s\n",
            crypto_has_aesni() ? "YES" : "NO",
            crypto_has_arm_crypto() ? "YES" : "NO",
            crypto_has_trng() ? "YES" : "NO");

    return CRYPTO_SUCCESS;
}

crypto_hw_features_t crypto_get_hw_support(void)
{
    return hw_features;
}

// Key management functions
crypto_key_t *crypto_generate_key(crypto_algorithm_t algorithm)
{
    crypto_key_t *key = (crypto_key_t *)kmalloc(sizeof(crypto_key_t));
    if (!key)
        return NULL;

    key->key_id = next_key_id++;
    key->algorithm = algorithm;
    key->is_private = false;
    key->next = crypto_keys;
    crypto_keys = key;

    // Generate key data based on algorithm
    switch (algorithm)
    {
    case CRYPTO_AES_128_ECB:
        key->key_size = 16; // 128 bits
        break;
    case CRYPTO_AES_256_ECB:
        key->key_size = 32; // 256 bits
        break;
    case CRYPTO_SHA256:
        key->key_size = 32;
        break;
    case CRYPTO_SHA512:
        key->key_size = 64;
        break;
    case CRYPTO_RSA_2048:
        key->key_size = 256; // 2048 bits
        break;
    case CRYPTO_RSA_4096:
        key->key_size = 512; // 4096 bits
        break;
    default:
        kfree(key);
        return NULL;
    }

    key->key_data = (uint8_t *)kmalloc(key->key_size);
    if (!key->key_data)
    {
        kfree(key);
        return NULL;
    }

    // Generate random key data
    crypto_random_bytes(key->key_data, key->key_size);

    return key;
}

crypto_key_t *crypto_import_key(crypto_algorithm_t algorithm, const void *key_data, size_t key_size)
{
    crypto_key_t *key = (crypto_key_t *)kmalloc(sizeof(crypto_key_t));
    if (!key)
        return NULL;

    key->key_id = next_key_id++;
    key->algorithm = algorithm;
    key->key_size = key_size;
    key->is_private = false;
    key->next = crypto_keys;
    crypto_keys = key;

    key->key_data = (uint8_t *)kmalloc(key_size);
    if (!key->key_data)
    {
        kfree(key);
        return NULL;
    }

    memcpy(key->key_data, key_data, key_size);

    return key;
}

int crypto_export_key(uint32_t key_id, void *buffer, size_t *buffer_size)
{
    crypto_key_t *key = crypto_find_key(key_id);
    if (!key)
        return CRYPTO_ERROR_INVALID_KEY;

    if (*buffer_size < key->key_size)
    {
        *buffer_size = key->key_size;
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(buffer, key->key_data, key->key_size);
    *buffer_size = key->key_size;

    return CRYPTO_SUCCESS;
}

int crypto_delete_key(uint32_t key_id)
{
    crypto_key_t **current = &crypto_keys;
    while (*current)
    {
        if ((*current)->key_id == key_id)
        {
            crypto_key_t *to_delete = *current;
            *current = (*current)->next;
            kfree(to_delete->key_data);
            kfree(to_delete);
            return CRYPTO_SUCCESS;
        }
        current = &(*current)->next;
    }
    return CRYPTO_ERROR_INVALID_KEY;
}

crypto_key_t *crypto_find_key(uint32_t key_id)
{
    crypto_key_t *current = crypto_keys;
    while (current)
    {
        if (current->key_id == key_id)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// AES encryption/decryption (simplified software implementation)
static int aes_encrypt_block(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext)
{
    // Simplified AES implementation (NOT cryptographically secure)
    // In production, use proper AES implementation
    for (int i = 0; i < 16; i++)
    {
        ciphertext[i] = plaintext[i] ^ key[i % 16];
    }
    return CRYPTO_SUCCESS;
}

static int aes_decrypt_block(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext)
{
    // Simplified AES implementation
    for (int i = 0; i < 16; i++)
    {
        plaintext[i] = ciphertext[i] ^ key[i % 16];
    }
    return CRYPTO_SUCCESS;
}

int crypto_encrypt(crypto_algorithm_t algorithm, uint32_t key_id,
                   const void *plaintext, size_t plaintext_len,
                   void *ciphertext, size_t *ciphertext_len,
                   const void *iv, size_t iv_len)
{
    crypto_key_t *key = crypto_find_key(key_id);
    if (!key)
        return CRYPTO_ERROR_INVALID_KEY;

    // For now, only support AES ECB modes
    if (algorithm != CRYPTO_AES_128_ECB && algorithm != CRYPTO_AES_256_ECB)
    {
        return CRYPTO_ERROR_UNSUPPORTED_ALGORITHM;
    }

    if (*ciphertext_len < plaintext_len)
    {
        *ciphertext_len = plaintext_len;
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Simple block-by-block encryption (simplified)
    const uint8_t *input = (const uint8_t *)plaintext;
    uint8_t *output = (uint8_t *)ciphertext;

    for (size_t i = 0; i < plaintext_len; i += 16)
    {
        size_t block_size = (plaintext_len - i >= 16) ? 16 : plaintext_len - i;
        aes_encrypt_block(key->key_data, input + i, output + i);
    }

    *ciphertext_len = plaintext_len;
    crypto_stats.aes_encryptions++;

    return CRYPTO_SUCCESS;
}

int crypto_decrypt(crypto_algorithm_t algorithm, uint32_t key_id,
                   const void *ciphertext, size_t ciphertext_len,
                   void *plaintext, size_t *plaintext_len,
                   const void *iv, size_t iv_len)
{
    crypto_key_t *key = crypto_find_key(key_id);
    if (!key)
        return CRYPTO_ERROR_INVALID_KEY;

    if (*plaintext_len < ciphertext_len)
    {
        *plaintext_len = ciphertext_len;
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Simple block-by-block decryption
    const uint8_t *input = (const uint8_t *)ciphertext;
    uint8_t *output = (uint8_t *)plaintext;

    for (size_t i = 0; i < ciphertext_len; i += 16)
    {
        size_t block_size = (ciphertext_len - i >= 16) ? 16 : ciphertext_len - i;
        aes_decrypt_block(key->key_data, input + i, output + i);
    }

    *plaintext_len = ciphertext_len;
    crypto_stats.aes_decryptions++;

    return CRYPTO_SUCCESS;
}

// Authenticated encryption (simplified)
int crypto_encrypt_aead(crypto_algorithm_t algorithm, uint32_t key_id,
                        const void *plaintext, size_t plaintext_len,
                        const void *aad, size_t aad_len,
                        void *ciphertext, size_t *ciphertext_len,
                        void *tag, size_t tag_len,
                        const void *iv, size_t iv_len)
{
    // Simplified AEAD implementation
    // In production, use proper GCM/CCM implementation
    int result = crypto_encrypt(algorithm, key_id, plaintext, plaintext_len,
                                ciphertext, ciphertext_len, iv, iv_len);

    if (result == CRYPTO_SUCCESS && tag && tag_len >= 16)
    {
        // Generate simple authentication tag
        uint8_t tag_data[16] = {0};
        crypto_hash(CRYPTO_SHA256, plaintext, plaintext_len, tag_data, &tag_len);
        memcpy(tag, tag_data, tag_len);
    }

    return result;
}

int crypto_decrypt_aead(crypto_algorithm_t algorithm, uint32_t key_id,
                        const void *ciphertext, size_t ciphertext_len,
                        const void *aad, size_t aad_len,
                        const void *tag, size_t tag_len,
                        void *plaintext, size_t *plaintext_len,
                        const void *iv, size_t iv_len)
{
    // Verify authentication tag first
    if (tag && tag_len > 0)
    {
        uint8_t computed_tag[32];
        size_t computed_tag_len = 32;
        crypto_hash(CRYPTO_SHA256, ciphertext, ciphertext_len, computed_tag, &computed_tag_len);

        // Simple constant-time comparison
        int auth_valid = 1;
        for (size_t i = 0; i < tag_len && i < computed_tag_len; i++)
        {
            if (((uint8_t *)tag)[i] != computed_tag[i])
            {
                auth_valid = 0;
            }
        }

        if (!auth_valid)
        {
            return CRYPTO_ERROR_AUTHENTICATION_FAILED;
        }
    }

    return crypto_decrypt(algorithm, key_id, ciphertext, ciphertext_len,
                          plaintext, plaintext_len, iv, iv_len);
}

// Hash functions (simplified SHA-256 implementation)
static uint32_t rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(uint32_t *state, const uint8_t *data)
{
    // Simplified SHA-256 transform (NOT cryptographically secure)
    // In production, use proper SHA-256 implementation
    for (int i = 0; i < 64; i++)
    {
        uint32_t temp = state[0] + data[i % 64];
        state[7] += temp;
        state[4] += rotr(temp, 6);
    }
}

int crypto_hash(crypto_algorithm_t algorithm,
                const void *data, size_t data_len,
                void *hash, size_t *hash_len)
{
    if (algorithm != CRYPTO_SHA256)
    {
        return CRYPTO_ERROR_UNSUPPORTED_ALGORITHM;
    }

    if (*hash_len < 32)
    {
        *hash_len = 32;
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Simplified SHA-256 implementation
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // Process data in 64-byte chunks
    const uint8_t *input = (const uint8_t *)data;
    for (size_t i = 0; i < data_len; i += 64)
    {
        size_t chunk_size = (data_len - i >= 64) ? 64 : data_len - i;
        uint8_t chunk[64] = {0};
        memcpy(chunk, input + i, chunk_size);
        sha256_transform(state, chunk);
    }

    // Output hash
    uint8_t *output = (uint8_t *)hash;
    for (int i = 0; i < 8; i++)
    {
        output[i * 4] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }

    *hash_len = 32;
    crypto_stats.hash_operations++;

    return CRYPTO_SUCCESS;
}

int crypto_hmac(crypto_algorithm_t algorithm, uint32_t key_id,
                const void *data, size_t data_len,
                void *hmac, size_t *hmac_len)
{
    crypto_key_t *key = crypto_find_key(key_id);
    if (!key)
        return CRYPTO_ERROR_INVALID_KEY;

    if (*hmac_len < 32)
    {
        *hmac_len = 32;
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Simplified HMAC implementation
    uint8_t ipad[64], opad[64];
    uint8_t temp_hash[32];

    // Prepare inner and outer padding
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (int i = 0; i < 64 && i < (int)key->key_size; i++)
    {
        ipad[i] ^= key->key_data[i];
        opad[i] ^= key->key_data[i];
    }

    // Inner hash
    uint8_t inner_data[128];
    memcpy(inner_data, ipad, 64);
    memcpy(inner_data + 64, data, data_len);
    crypto_hash(algorithm, inner_data, 64 + data_len, temp_hash, hmac_len);

    // Outer hash
    uint8_t outer_data[96];
    memcpy(outer_data, opad, 64);
    memcpy(outer_data + 64, temp_hash, 32);
    crypto_hash(algorithm, outer_data, 96, hmac, hmac_len);

    return CRYPTO_SUCCESS;
}

// Random number generation
int crypto_random_bytes(void *buffer, size_t size)
{
    static uint32_t seed = 0x12345678;
    uint8_t *buf = (uint8_t *)buffer;

    for (size_t i = 0; i < size; i++)
    {
        // Linear congruential generator (NOT cryptographically secure)
        seed = seed * 1103515245 + 12345;
        buf[i] = (seed >> 16) & 0xFF;
    }

    return CRYPTO_SUCCESS;
}

int crypto_random_int(uint32_t *value)
{
    return crypto_random_bytes(value, sizeof(uint32_t));
}

// RSA functions (simplified)
int crypto_rsa_generate_keypair(crypto_algorithm_t algorithm, uint32_t *public_key_id, uint32_t *private_key_id)
{
    // Simplified RSA key generation
    // In production, use proper RSA implementation

    crypto_key_t *public_key = crypto_generate_key(algorithm);
    crypto_key_t *private_key = crypto_generate_key(algorithm);

    if (!public_key || !private_key)
    {
        if (public_key)
            crypto_delete_key(public_key->key_id);
        if (private_key)
            crypto_delete_key(private_key->key_id);
        return CRYPTO_ERROR_ENCRYPTION_FAILED;
    }

    public_key->is_private = false;
    private_key->is_private = true;

    *public_key_id = public_key->key_id;
    *private_key_id = private_key->key_id;

    crypto_stats.rsa_operations++;
    return CRYPTO_SUCCESS;
}

// ECC functions (simplified)
int crypto_ecc_generate_keypair(crypto_algorithm_t algorithm, uint32_t *public_key_id, uint32_t *private_key_id)
{
    // Simplified ECC key generation
    crypto_key_t *public_key = crypto_generate_key(algorithm);
    crypto_key_t *private_key = crypto_generate_key(algorithm);

    if (!public_key || !private_key)
    {
        if (public_key)
            crypto_delete_key(public_key->key_id);
        if (private_key)
            crypto_delete_key(private_key->key_id);
        return CRYPTO_ERROR_ENCRYPTION_FAILED;
    }

    public_key->is_private = false;
    private_key->is_private = true;

    *public_key_id = public_key->key_id;
    *private_key_id = private_key->key_id;

    crypto_stats.ecc_operations++;
    return CRYPTO_SUCCESS;
}

// TLS/SSL functions
tls_context_t *tls_create_context(void)
{
    tls_context_t *ctx = (tls_context_t *)kmalloc(sizeof(tls_context_t));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(tls_context_t));
    ctx->session_id = next_key_id++; // Reuse key ID counter
    ctx->handshake_complete = false;
    ctx->protocol_version = 0x0303; // TLS 1.2

    // Add to context list
    ctx->next = tls_contexts;
    tls_contexts = ctx;

    crypto_stats.tls_handshakes++;
    return ctx;
}

int tls_destroy_context(tls_context_t *ctx)
{
    if (!ctx)
        return CRYPTO_ERROR_INVALID_DATA;

    tls_context_t **current = &tls_contexts;
    while (*current)
    {
        if (*current == ctx)
        {
            *current = ctx->next;
            if (ctx->server_key)
                crypto_delete_key(ctx->server_key->key_id);
            if (ctx->client_key)
                crypto_delete_key(ctx->client_key->key_id);
            kfree(ctx);
            return CRYPTO_SUCCESS;
        }
        current = &(*current)->next;
    }

    return CRYPTO_ERROR_INVALID_DATA;
}

// Secure memory management
void *crypto_secure_alloc(size_t size)
{
    void *ptr = kmalloc(size);
    if (ptr)
    {
        crypto_secure_clear(ptr, size);
    }
    return ptr;
}

void crypto_secure_free(void *ptr, size_t size)
{
    if (ptr)
    {
        crypto_secure_clear(ptr, size);
        kfree(ptr);
    }
}

void crypto_secure_clear(void *ptr, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++)
    {
        p[i] = 0;
    }
}

crypto_stats_t *crypto_get_stats(void)
{
    return &crypto_stats;
}
