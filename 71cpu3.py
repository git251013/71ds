#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// Target address
const std::string TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";

// secp256k1 curve order
const char* SECP256K1_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Base58 characters
const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Global variables
std::atomic<bool> found(false);
std::atomic<uint64_t> keys_checked(0);
std::mutex output_mutex;

// Base58 encoding
std::string base58_encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";
    
    // Count leading zeros
    size_t zero_count = 0;
    while (zero_count < data.size() && data[zero_count] == 0) {
        zero_count++;
    }
    
    // Convert to Base58
    std::vector<unsigned char> digits;
    digits.resize(data.size() * 2);
    size_t digitslen = 1;
    
    for (size_t i = zero_count; i < data.size(); i++) {
        uint32_t carry = static_cast<uint32_t>(data[i]);
        
        for (size_t j = 0; j < digitslen; j++) {
            carry += static_cast<uint32_t>(digits[j]) << 8;
            digits[j] = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }
        
        while (carry > 0) {
            digits[digitslen++] = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }
    }
    
    // Build result string
    std::string result;
    result.reserve(zero_count + digitslen);
    
    // Add leading zeros
    for (size_t i = 0; i < zero_count; i++) {
        result.push_back(BASE58_CHARS[0]);
    }
    
    // Add Base58 digits
    for (size_t i = 0; i < digitslen; i++) {
        result.push_back(BASE58_CHARS[digits[digitslen - 1 - i]]);
    }
    
    return result;
}

// Check if private key is valid
bool is_valid_private_key(const BIGNUM* private_key, const BIGNUM* curve_order) {
    if (BN_is_zero(private_key)) return false;
    if (BN_cmp(private_key, curve_order) >= 0) return false;
    return true;
}

// Convert private key to WIF compressed format
std::string private_key_to_wif_compressed(const BIGNUM* private_key) {
    if (!private_key) return "";
    
    std::vector<unsigned char> private_key_bytes(32);
    if (BN_bn2binpad(private_key, private_key_bytes.data(), 32) != 32) {
        return "";
    }
    
    std::vector<unsigned char> wif_bytes;
    wif_bytes.reserve(38);
    
    wif_bytes.push_back(0x80);
    wif_bytes.insert(wif_bytes.end(), private_key_bytes.begin(), private_key_bytes.end());
    wif_bytes.push_back(0x01);
    
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    
    SHA256(wif_bytes.data(), wif_bytes.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    
    wif_bytes.insert(wif_bytes.end(), hash2, hash2 + 4);
    
    return base58_encode(wif_bytes);
}

// Generate compressed Bitcoin address from private key
std::string private_key_to_compressed_address(const BIGNUM* private_key, const BIGNUM* curve_order) {
    if (!private_key || !is_valid_private_key(private_key, curve_order)) {
        return "";
    }
    
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) return "";
    
    if (EC_KEY_set_private_key(ec_key, private_key) != 1) {
        EC_KEY_free(ec_key);
        return "";
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* public_point = EC_POINT_new(group);
    if (!public_point) {
        EC_KEY_free(ec_key);
        return "";
    }
    
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(public_point);
        EC_KEY_free(ec_key);
        return "";
    }
    
    std::string result;
    
    if (EC_POINT_mul(group, public_point, private_key, NULL, NULL, ctx) == 1) {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        
        if (x && y && EC_POINT_get_affine_coordinates(group, public_point, x, y, ctx) == 1) {
            std::vector<unsigned char> public_key;
            public_key.reserve(33);
            
            public_key.push_back(BN_is_odd(y) ? 0x03 : 0x02);
            
            std::vector<unsigned char> x_bytes(32);
            BN_bn2binpad(x, x_bytes.data(), 32);
            public_key.insert(public_key.end(), x_bytes.begin(), x_bytes.end());
            
            unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
            SHA256(public_key.data(), public_key.size(), sha256_hash);
            
            unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
            RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);
            
            std::vector<unsigned char> address_bytes;
            address_bytes.reserve(25);
            
            address_bytes.push_back(0x00);
            address_bytes.insert(address_bytes.end(), ripemd160_hash, ripemd160_hash + 20);
            
            unsigned char checksum1[SHA256_DIGEST_LENGTH];
            unsigned char checksum2[SHA256_DIGEST_LENGTH];
            
            SHA256(address_bytes.data(), address_bytes.size(), checksum1);
            SHA256(checksum1, SHA256_DIGEST_LENGTH, checksum2);
            
            address_bytes.insert(address_bytes.end(), checksum2, checksum2 + 4);
            
            result = base58_encode(address_bytes);
        }
        
        if (x) BN_free(x);
        if (y) BN_free(y);
    }
    
    BN_CTX_free(ctx);
    EC_POINT_free(public_point);
    EC_KEY_free(ec_key);
    
    return result;
}

// Generate valid private key in range
bool generate_private_key_in_range(BIGNUM* result, const BIGNUM* min_key, const BIGNUM* max_key, 
                                  const BIGNUM* curve_order, BN_CTX* ctx) {
    if (!result || !min_key || !max_key || !curve_order || !ctx) return false;
    
    BIGNUM* range = BN_CTX_get(ctx);
    BIGNUM* temp = BN_CTX_get(ctx);
    if (!range || !temp) return false;
    
    if (BN_sub(range, max_key, min_key) != 1) return false;
    if (BN_rand_range(temp, range) != 1) return false;
    if (BN_add(result, min_key, temp) != 1) return false;
    
    return is_valid_private_key(result, curve_order);
}

// Worker thread function
void worker_thread(int thread_id, const BIGNUM* min_key, const BIGNUM* max_key, 
                  const BIGNUM* curve_order) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return;
    
    BIGNUM* private_key = BN_new();
    if (!private_key) {
        BN_CTX_free(ctx);
        return;
    }
    
    uint64_t local_count = 0;
    auto last_report = std::chrono::steady_clock::now();
    
    while (!found) {
        if (!generate_private_key_in_range(private_key, min_key, max_key, curve_order, ctx)) {
            continue;
        }
        
        std::string address = private_key_to_compressed_address(private_key, curve_order);
        if (address.empty()) {
            continue;
        }
        
        local_count++;
        
        if (address == TARGET_ADDRESS) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "\n*** FOUND MATCHING ADDRESS! ***" << std::endl;
            std::cout << "Target: " << TARGET_ADDRESS << std::endl;
            
            std::string wif = private_key_to_wif_compressed(private_key);
            std::cout << "WIF: " << wif << std::endl;
            
            char* hex_key = BN_bn2hex(private_key);
            if (hex_key) {
                std::cout << "Private Key (hex): " << hex_key << std::endl;
                
                std::ofstream file("found_key.txt");
                if (file.is_open()) {
                    auto now = std::chrono::system_clock::now();
                    std::time_t time = std::chrono::system_clock::to_time_t(now);
                    
                    file << "Target: " << TARGET_ADDRESS << "\n";
                    file << "WIF: " << wif << "\n";
                    file << "Private Key: " << hex_key << "\n";
                    file << "Time: " << std::ctime(&time);
                    file << "Thread: " << thread_id << "\n";
                    file.close();
                }
                
                OPENSSL_free(hex_key);
            }
            
            found = true;
            break;
        }
        
        auto now = std::chrono::steady_clock::now();
        if (now - last_report > std::chrono::seconds(5)) {
            keys_checked += local_count;
            local_count = 0;
            last_report = now;
        }
    }
    
    keys_checked += local_count;
    BN_free(private_key);
    BN_CTX_free(ctx);
}

// Progress monitor
void progress_monitor() {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_count = 0;
    auto last_time = start_time;
    
    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto current_time = std::chrono::steady_clock::now();
        uint64_t current_count = keys_checked.load();
        double elapsed = std::chrono::duration<double>(current_time - start_time).count();
        
        double avg_speed = (elapsed > 0) ? current_count / elapsed : 0;
        double time_diff = std::chrono::duration<double>(current_time - last_time).count();
        double instant_speed = (time_diff > 0) ? (current_count - last_count) / time_diff : 0;
        
        std::cout << "\n=== Progress ===" << std::endl;
        std::cout << "Time: " << std::fixed << std::setprecision(1) << elapsed << "s" << std::endl;
        std::cout << "Keys: " << current_count << std::endl;
        std::cout << "Speed: " << std::fixed << std::setprecision(0) << avg_speed << "/s" << std::endl;
        std::cout << "Current: " << std::fixed << std::setprecision(0) << instant_speed << "/s" << std::endl;
        std::cout << "================\n" << std::endl;
        
        last_count = current_count;
        last_time = current_time;
    }
}

int main() {
    std::cout << "=== Bitcoin Private Key Brute Force ===" << std::endl;
    std::cout << "Target: " << TARGET_ADDRESS << std::endl;
    std::cout << "Range: 2^70 to 2^71" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Create curve order
    BIGNUM* curve_order = BN_new();
    if (!curve_order || BN_hex2bn(&curve_order, SECP256K1_ORDER_HEX) == 0) {
        std::cerr << "Error: Failed to create curve order" << std::endl;
        if (curve_order) BN_free(curve_order);
        return 1;
    }
    
    // Create search range using BN_set_bit
    BIGNUM* min_key = BN_new();
    BIGNUM* max_key = BN_new();
    
    if (!min_key || !max_key) {
        std::cerr << "Error: Failed to create range keys" << std::endl;
        BN_free(curve_order);
        if (min_key) BN_free(min_key);
        if (max_key) BN_free(max_key);
        return 1;
    }
    
    // Set 2^70 and 2^71 using BN_set_bit
    BN_zero(min_key);
    BN_set_bit(min_key, 70);  // 2^70
    
    BN_zero(max_key);
    BN_set_bit(max_key, 71);  // 2^71
    
    // Verify range
    if (BN_cmp(min_key, max_key) >= 0) {
        std::cerr << "Error: Invalid range" << std::endl;
        BN_free(curve_order);
        BN_free(min_key);
        BN_free(max_key);
        return 1;
    }
    
    // Determine thread count
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    if (num_threads > 16) num_threads = 16;
    
    std::cout << "Using " << num_threads << " threads" << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Start monitor thread
    std::thread monitor(progress_monitor);
    
    // Start worker threads
    std::vector<std::thread> workers;
    for (unsigned int i = 0; i < num_threads; i++) {
        workers.emplace_back(worker_thread, i, min_key, max_key, curve_order);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Wait for workers
    for (auto& thread : workers) {
        if (thread.joinable()) thread.join();
    }
    
    // Wait for monitor
    if (monitor.joinable()) monitor.join();
    
    auto end_time = std::chrono::steady_clock::now();
    double total_time = std::chrono::duration<double>(end_time - start_time).count();
    
    std::cout << "\nFinished" << std::endl;
    std::cout << "Total time: " << total_time << "s" << std::endl;
    std::cout << "Total keys: " << keys_checked.load() << std::endl;
    
    if (total_time > 0) {
        std::cout << "Average speed: " << keys_checked.load() / total_time << "/s" << std::endl;
    }
    
    // Cleanup
    BN_free(curve_order);
    BN_free(min_key);
    BN_free(max_key);
    
    EVP_cleanup();
    
    return 0;
}
