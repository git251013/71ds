#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <cstring>

// CUDA headers
#include <cuda_runtime.h>
#include <cuda.h>
#include <device_launch_parameters.h>

// OpenSSL headers for hash functions
#include <openssl/sha.h>
#include <openssl/ripemd.h>

using namespace std;

// Secp256k1 curve parameters
static const uint64_t SECP256K1_N[4] = {
    0xBFD25E8CD0364141ULL, 0xAAAEDCE6AF48A03BULL, 
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

static const uint64_t SECP256K1_P[4] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL
};

// Base point (generator) coordinates - 修正后的正确值
static const uint64_t GX[4] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
};

static const uint64_t GY[4] = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

// 256-bit integer structure
struct uint256_t {
    uint64_t data[4];
    
    __device__ __host__ uint256_t() {
        data[0] = data[1] = data[2] = data[3] = 0;
    }
    
    __device__ __host__ uint256_t(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
        data[0] = a; data[1] = b; data[2] = c; data[3] = d;
    }
    
    __device__ __host__ uint256_t(const uint256_t& other) {
        data[0] = other.data[0];
        data[1] = other.data[1];
        data[2] = other.data[2];
        data[3] = other.data[3];
    }
    
    __device__ __host__ uint256_t& operator=(const uint256_t& other) {
        if (this != &other) {
            data[0] = other.data[0];
            data[1] = other.data[1];
            data[2] = other.data[2];
            data[3] = other.data[3];
        }
        return *this;
    }
};

// Elliptic curve point structure
struct Point {
    uint256_t x;
    uint256_t y;
    bool infinity;
    
    __device__ __host__ Point() : infinity(true) {}
    __device__ __host__ Point(const uint256_t& x_val, const uint256_t& y_val) 
        : x(x_val), y(y_val), infinity(false) {}
};

// Compare two 256-bit integers
__device__ int compare_uint256(const uint256_t& a, const uint256_t& b) {
    for (int i = 3; i >= 0; i--) {
        if (a.data[i] < b.data[i]) return -1;
        if (a.data[i] > b.data[i]) return 1;
    }
    return 0;
}

// Check if a 256-bit integer is zero
__device__ bool is_zero_uint256(const uint256_t& a) {
    return (a.data[0] == 0 && a.data[1] == 0 && a.data[2] == 0 && a.data[3] == 0);
}

// Add two 256-bit integers modulo P
__device__ uint256_t add_mod_p(const uint256_t& a, const uint256_t& b) {
    uint64_t result[4];
    uint64_t carry = 0;
    
    // Add with carry
    for (int i = 0; i < 4; i++) {
        uint64_t sum = a.data[i] + b.data[i] + carry;
        result[i] = sum;
        carry = (sum < a.data[i]) ? 1 : ((sum == a.data[i] && carry) ? 1 : 0);
    }
    
    // Modulo P reduction
    uint256_t p = {SECP256K1_P[0], SECP256K1_P[1], SECP256K1_P[2], SECP256K1_P[3]};
    
    if (carry || compare_uint256({result[0], result[1], result[2], result[3]}, p) >= 0) {
        carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t old_val = result[i];
            result[i] -= p.data[i] + carry;
            carry = (old_val < result[i]) ? 1 : ((old_val == result[i] && carry) ? 1 : 0);
        }
    }
    
    return {result[0], result[1], result[2], result[3]};
}

// Subtract two 256-bit integers modulo P
__device__ uint256_t sub_mod_p(const uint256_t& a, const uint256_t& b) {
    uint64_t result[4];
    uint64_t borrow = 0;
    
    // Subtract with borrow
    for (int i = 0; i < 4; i++) {
        uint64_t old_val = a.data[i];
        result[i] = a.data[i] - b.data[i] - borrow;
        borrow = (old_val < result[i]) ? 1 : ((old_val == result[i] && borrow) ? 1 : 0);
    }
    
    // Handle underflow by adding P
    if (borrow) {
        uint256_t p = {SECP256K1_P[0], SECP256K1_P[1], SECP256K1_P[2], SECP256K1_P[3]};
        return add_mod_p({result[0], result[1], result[2], result[3]}, p);
    }
    
    return {result[0], result[1], result[2], result[3]};
}

// 64-bit rotate right
__device__ uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// Multiply two 256-bit integers modulo P
__device__ uint256_t mul_mod_p(const uint256_t& a, const uint256_t& b) {
    uint64_t product[8] = {0};
    
    // Multiply a and b using 64-bit multiplication
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            int pos = i + j;
            if (pos >= 8) continue;
            
            // Perform 64-bit multiplication
            unsigned long long hi, lo;
            lo = (unsigned long long)a.data[i] * b.data[j];
            hi = __umul64hi(a.data[i], b.data[j]);
            
            // Add to product with carry
            uint64_t old_lo = product[pos];
            product[pos] += lo;
            uint64_t carry_lo = (product[pos] < old_lo) ? 1 : 0;
            
            uint64_t old_hi = product[pos + 1];
            product[pos + 1] += hi + carry_lo;
        }
    }
    
    // Modular reduction (simplified Barrett reduction)
    uint256_t p = {SECP256K1_P[0], SECP256K1_P[1], SECP256K1_P[2], SECP256K1_P[3]};
    uint256_t temp = {product[0], product[1], product[2], product[3]};
    
    // Simple modular reduction - subtract P until temp < P
    while (compare_uint256(temp, p) >= 0) {
        temp = sub_mod_p(temp, p);
    }
    
    return temp;
}

// Modular inverse using Fermat's Little Theorem: a^(-1) = a^(p-2) mod p
__device__ uint256_t inv_mod_p(const uint256_t& a) {
    if (is_zero_uint256(a)) {
        return a;
    }
    
    uint256_t result = {1, 0, 0, 0};
    uint256_t exponent = {SECP256K1_P[0]-2, SECP256K1_P[1], SECP256K1_P[2], SECP256K1_P[3]};
    uint256_t base = a;
    
    // Modular exponentiation
    for (int i = 0; i < 256; i++) {
        // Check each bit of the exponent
        int word_idx = i / 64;
        int bit_idx = i % 64;
        
        if (exponent.data[word_idx] & (1ULL << bit_idx)) {
            result = mul_mod_p(result, base);
        }
        base = mul_mod_p(base, base);
    }
    
    return result;
}

// Point doubling
__device__ Point point_double(const Point& p) {
    if (p.infinity) return p;
    
    // lambda = (3 * x^2) / (2 * y) mod p
    uint256_t x_squared = mul_mod_p(p.x, p.x);
    uint256_t three_x_squared = mul_mod_p({3, 0, 0, 0}, x_squared);
    uint256_t two_y = mul_mod_p({2, 0, 0, 0}, p.y);
    uint256_t lambda = mul_mod_p(three_x_squared, inv_mod_p(two_y));
    
    // x3 = lambda^2 - 2*x mod p
    uint256_t lambda_squared = mul_mod_p(lambda, lambda);
    uint256_t two_x = mul_mod_p({2, 0, 0, 0}, p.x);
    uint256_t x3 = sub_mod_p(lambda_squared, two_x);
    
    // y3 = lambda * (x - x3) - y mod p
    uint256_t x_diff = sub_mod_p(p.x, x3);
    uint256_t lambda_x_diff = mul_mod_p(lambda, x_diff);
    uint256_t y3 = sub_mod_p(lambda_x_diff, p.y);
    
    return Point(x3, y3);
}

// Point addition
__device__ Point point_add(const Point& p1, const Point& p2) {
    if (p1.infinity) return p2;
    if (p2.infinity) return p1;
    
    if (compare_uint256(p1.x, p2.x) == 0) {
        if (compare_uint256(p1.y, p2.y) == 0) {
            return point_double(p1);
        } else {
            Point result;
            result.infinity = true;
            return result;
        }
    }
    
    // lambda = (y2 - y1) / (x2 - x1) mod p
    uint256_t y_diff = sub_mod_p(p2.y, p1.y);
    uint256_t x_diff = sub_mod_p(p2.x, p1.x);
    uint256_t lambda = mul_mod_p(y_diff, inv_mod_p(x_diff));
    
    // x3 = lambda^2 - x1 - x2 mod p
    uint256_t lambda_squared = mul_mod_p(lambda, lambda);
    uint256_t x_sum = add_mod_p(p1.x, p2.x);
    uint256_t x3 = sub_mod_p(lambda_squared, x_sum);
    
    // y3 = lambda * (x1 - x3) - y1 mod p
    uint256_t x1_x3 = sub_mod_p(p1.x, x3);
    uint256_t lambda_x1_x3 = mul_mod_p(lambda, x1_x3);
    uint256_t y3 = sub_mod_p(lambda_x1_x3, p1.y);
    
    return Point(x3, y3);
}

// Scalar multiplication using double-and-add algorithm
__device__ Point scalar_multiply(const uint256_t& k, const Point& point) {
    Point result;
    result.infinity = true;
    
    Point current = point;
    
    for (int i = 0; i < 256; i++) {
        int word_idx = i / 64;
        int bit_idx = i % 64;
        
        if (k.data[word_idx] & (1ULL << bit_idx)) {
            if (result.infinity) {
                result = current;
            } else {
                result = point_add(result, current);
            }
        }
        current = point_double(current);
    }
    
    return result;
}

// SHA-256 implementation for GPU
__device__ void sha256_gpu(const unsigned char* data, size_t len, unsigned char* hash) {
    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // SHA-256 constants
    const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    // Process the input data in 512-bit chunks
    size_t chunk_count = (len + 8 + 64) / 64;
    
    for (size_t chunk = 0; chunk < chunk_count; chunk++) {
        uint32_t w[64] = {0};
        
        // Copy chunk into first 16 words of message schedule
        for (int i = 0; i < 16; i++) {
            size_t pos = chunk * 64 + i * 4;
            if (pos < len) {
                w[i] = (uint32_t)data[pos] << 24;
                if (pos + 1 < len) w[i] |= (uint32_t)data[pos + 1] << 16;
                if (pos + 2 < len) w[i] |= (uint32_t)data[pos + 2] << 8;
                if (pos + 3 < len) w[i] |= (uint32_t)data[pos + 3];
            }
        }
        
        // Padding for last chunk
        if (chunk == chunk_count - 1) {
            size_t pos = chunk * 64;
            if (pos <= len) {
                size_t pad_pos = len - pos;
                if (pad_pos < 64) {
                    if (pad_pos < len) {
                        w[pad_pos / 4] |= 0x80 << (24 - (pad_pos % 4) * 8);
                    }
                    
                    // Add length in bits at the end (big-endian)
                    uint64_t bit_len = len * 8;
                    w[14] = (bit_len >> 32) & 0xFFFFFFFF;
                    w[15] = bit_len & 0xFFFFFFFF;
                }
            }
        }
        
        // Extend the first 16 words into the remaining 48 words
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        // Initialize working variables
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
        
        // Compression function main loop
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h_val + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // Add compressed chunk to current hash value
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
    }
    
    // Produce final hash value (big-endian)
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (h[i] >> 24) & 0xFF;
        hash[i*4+1] = (h[i] >> 16) & 0xFF;
        hash[i*4+2] = (h[i] >> 8) & 0xFF;
        hash[i*4+3] = h[i] & 0xFF;
    }
}

// RIPEMD-160 implementation for GPU
__device__ void ripemd160_gpu(const unsigned char* data, size_t len, unsigned char* hash) {
    // Initialization constants
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476, h4 = 0xC3D2E1F0;
    
    // Process message in 512-bit chunks
    for (size_t i = 0; i < len; i += 64) {
        uint32_t block[16];
        size_t block_len = (len - i > 64) ? 64 : len - i;
        
        // Copy data into block (little-endian)
        for (int j = 0; j < 16; j++) {
            block[j] = 0;
            for (int k = 0; k < 4; k++) {
                size_t pos = i + j * 4 + k;
                if (pos < len) {
                    block[j] |= (uint32_t)data[pos] << (k * 8);
                }
            }
        }
        
        // RIPEMD-160 round functions would go here
        // For now, use a simplified transformation
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        
        // This is a placeholder - actual RIPEMD-160 has 80 rounds
        for (int j = 0; j < 16; j++) {
            uint32_t f = (b & c) | (~b & d);
            uint32_t temp = a + f + block[j] + 0x00000000;
            a = e;
            e = d;
            d = rotr32(c, 10);
            c = b;
            b = temp;
        }
        
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    
    // Final hash value (little-endian)
    hash[0] = h0 & 0xFF; hash[1] = (h0 >> 8) & 0xFF; hash[2] = (h0 >> 16) & 0xFF; hash[3] = (h0 >> 24) & 0xFF;
    hash[4] = h1 & 0xFF; hash[5] = (h1 >> 8) & 0xFF; hash[6] = (h1 >> 16) & 0xFF; hash[7] = (h1 >> 24) & 0xFF;
    hash[8] = h2 & 0xFF; hash[9] = (h2 >> 8) & 0xFF; hash[10] = (h2 >> 16) & 0xFF; hash[11] = (h2 >> 24) & 0xFF;
    hash[12] = h3 & 0xFF; hash[13] = (h3 >> 8) & 0xFF; hash[14] = (h3 >> 16) & 0xFF; hash[15] = (h3 >> 24) & 0xFF;
    hash[16] = h4 & 0xFF; hash[17] = (h4 >> 8) & 0xFF; hash[18] = (h4 >> 16) & 0xFF; hash[19] = (h4 >> 24) & 0xFF;
}
// Base58 encoding function
__device__ void base58_encode(const unsigned char* data, int len, char* result) {
    // Handle leading zeros
    int zeros = 0;
    while (zeros < len && data[zeros] == 0) {
        zeros++;
    }
    
    // Convert to base58
    unsigned char b58[256] = {0};
    int b58_len = 0;
    
    for (int i = zeros; i < len; i++) {
        int carry = data[i];
        int j = 0;
        
        for (int k = b58_len - 1; k >= 0; k--, j++) {
            carry += 256 * b58[k];
            b58[k] = carry % 58;
            carry /= 58;
        }
        
        while (carry > 0) {
            for (int k = b58_len; k > 0; k--) {
                b58[k] = b58[k-1];
            }
            b58[0] = carry % 58;
            carry /= 58;
            b58_len++;
        }
    }
    
    // Build the result string
    int idx = 0;
    for (int i = 0; i < zeros; i++) {
        result[idx++] = '1';
    }
    
    for (int i = 0; i < b58_len; i++) {
        result[idx++] = BASE58_CHARS[b58[i]];
    }
    result[idx] = '\0';
}

// Convert public key to Bitcoin address
__device__ void public_key_to_address(const Point& pub_key, char* address) {
    unsigned char pub_key_bytes[65];
    pub_key_bytes[0] = 0x04; // Uncompressed public key prefix
    
    // Convert x coordinate to bytes (big-endian)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            pub_key_bytes[1 + i * 8 + (7 - j)] = (pub_key.x.data[3 - i] >> (j * 8)) & 0xFF;
        }
    }
    
    // Convert y coordinate to bytes (big-endian)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            pub_key_bytes[33 + i * 8 + (7 - j)] = (pub_key.y.data[3 - i] >> (j * 8)) & 0xFF;
        }
    }
    
    // SHA-256 hash
    unsigned char sha256_hash[32];
    sha256_gpu(pub_key_bytes, 65, sha256_hash);
    
    // RIPEMD-160 hash
    unsigned char ripemd160_hash[20];
    ripemd160_gpu(sha256_hash, 32, ripemd160_hash);
    
    // Add version byte (0x00 for mainnet)
    unsigned char extended[21];
    extended[0] = 0x00;
    for (int i = 0; i < 20; i++) {
        extended[i+1] = ripemd160_hash[i];
    }
    
    // Double SHA-256 for checksum
    unsigned char checksum_hash1[32], checksum_hash2[32];
    sha256_gpu(extended, 21, checksum_hash1);
    sha256_gpu(checksum_hash1, 32, checksum_hash2);
    
    // Combine extended payload with checksum
    unsigned char address_bytes[25];
    for (int i = 0; i < 21; i++) {
        address_bytes[i] = extended[i];
    }
    for (int i = 0; i < 4; i++) {
        address_bytes[21 + i] = checksum_hash2[i];
    }
    
    // Base58 encode
    base58_encode(address_bytes, 25, address);
}

// Target address
__constant__ char TARGET_ADDRESS[] = "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR";

// Main CUDA kernel for private key search
__global__ void search_private_keys_kernel(uint64_t start, uint64_t range_size, int* found, uint64_t* found_key) {
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread_id >= range_size) return;
    
    // Calculate private key for this thread
    uint64_t private_key_val = start + thread_id;
    uint256_t private_key = {private_key_val, 0, 0, 0};
    
    // Check if private key is within curve order
    uint256_t curve_order = {SECP256K1_N[0], SECP256K1_N[1], SECP256K1_N[2], SECP256K1_N[3]};
    if (compare_uint256(private_key, curve_order) >= 0) {
        return;
    }
    
    // Generate base point
    Point G;
    G.infinity = false;
    G.x = {GX[0], GX[1], GX[2], GX[3]};
    G.y = {GY[0], GY[1], GY[2], GY[3]};
    
    // Compute public key
    Point public_key = scalar_multiply(private_key, G);
    if (public_key.infinity) {
        return;
}
// Generate Bitcoin address
    char address[40] = {0};
    public_key_to_address(public_key, address);
    
    // Compare with target address
    bool match = true;
    for (int i = 0; i < 34; i++) {
        if (address[i] != TARGET_ADDRESS[i]) {
            match = false;
            break;
        }
        if (TARGET_ADDRESS[i] == '\0') break;
    }
    
    // If match found, store result
    if (match) {
        atomicExch(found, 1);
        atomicExch(found_key, private_key_val);
    }
}

// Check CUDA errors
void check_cuda_error(cudaError_t err, const char* msg) {
    if (err != cudaSuccess) {
        cerr << "CUDA Error: " << msg << " - " << cudaGetErrorString(err) << endl;
        exit(1);
    }
}

int main() {
    cout << "=== Bitcoin Private Key Search ===" << endl;
    cout << "Target Address: " << TARGET_ADDRESS << endl;
    
    // Search range
    uint64_t start_range = 970436974004923190478ULL;
    uint64_t end_range = 970436974005023790478ULL;
    uint64_t range_size = end_range - start_range + 1;
    
    cout << "Search Range: " << start_range << " to " << end_range << endl;
    cout << "Total Keys: " << range_size << endl;
    
    if (range_size == 0) {
        cerr << "Error: Invalid range size" << endl;
        return 1;
    }
    
    // Device memory allocation
    int* d_found;
    uint64_t* d_found_key;
    
    check_cuda_error(cudaMalloc(&d_found, sizeof(int)), "Failed to allocate d_found");
    check_cuda_error(cudaMalloc(&d_found_key, sizeof(uint64_t)), "Failed to allocate d_found_key");
    
    // Initialize device memory
    int zero = 0;
    uint64_t zero_key = 0;
    check_cuda_error(cudaMemcpy(d_found, &zero, sizeof(int), cudaMemcpyHostToDevice), 
                    "Failed to initialize d_found");
    check_cuda_error(cudaMemcpy(d_found_key, &zero_key, sizeof(uint64_t), cudaMemcpyHostToDevice),
                    "Failed to initialize d_found_key");
    
    // Calculate grid and block sizes
    int block_size = 256;
    int grid_size = (range_size + block_size - 1) / block_size;
    
    // Limit grid size to avoid GPU memory issues
    if (grid_size > 65535) {
        grid_size = 65535;
        block_size = (range_size + grid_size - 1) / grid_size;
    }
    
    cout << "CUDA Configuration: " << grid_size << " blocks x " << block_size << " threads" << endl;
    cout << "Starting search..." << endl;
    
    auto start_time = chrono::high_resolution_clock::now();
    
    // Launch CUDA kernel
    search_private_keys_kernel<<<grid_size, block_size>>>(
        start_range, range_size, d_found, d_found_key);
    
    check_cuda_error(cudaGetLastError(), "Kernel launch failed");
    check_cuda_error(cudaDeviceSynchronize(), "Device synchronization failed");
    
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    
    // Check results
    int found;
    uint64_t found_key;
    
    check_cuda_error(cudaMemcpy(&found, d_found, sizeof(int), cudaMemcpyDeviceToHost),
                    "Failed to copy result from device");
    check_cuda_error(cudaMemcpy(&found_key, d_found_key, sizeof(uint64_t), cudaMemcpyDeviceToHost),
                    "Failed to copy found key from device");
    
    cout << "Search completed in " << duration.count() << " ms" << endl;
    
    if (found) {
        cout << "*** PRIVATE KEY FOUND! ***" << endl;
        cout << "Private Key (decimal): " << found_key << endl;
        
        stringstream hex_stream;
        hex_stream << hex << found_key;
        cout << "Private Key (hexadecimal): " << hex_stream.str() << endl;
        
        // Verify the private key
        cout << "Verification would be performed here..." << endl;
    } else {
        cout << "Private key not found in the specified range." << endl;
    }
    
    // Cleanup
    cudaFree(d_found);
    cudaFree(d_found_key);
    
    cout << "=== Search Finished ===" << endl;
    
    return 0;
}
