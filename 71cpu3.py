#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <random>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// 目标地址
const std::string TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";

// 范围定义 (2^70 到 2^71)
// 使用字符串初始化大数，避免位移溢出
const char* MIN_KEY_STR = "1180591620717411303424";  // 2^70
const char* MAX_KEY_STR = "2361183241434822606848";  // 2^71

// Base58字符集
const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// 全局变量
std::atomic<bool> found(false);
std::atomic<uint64_t> keys_checked(0);
std::mutex output_mutex;

// Base58编码函数
std::string base58_encode(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digits(data.size() * 138 / 100 + 1);
    size_t digitslen = 1;
    
    for (size_t i = 0; i < data.size(); i++) {
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
    
    std::string result;
    for (size_t i = 0; i < data.size() && data[i] == 0; i++) {
        result.push_back(BASE58_CHARS[0]);
    }
    
    for (size_t i = 0; i < digitslen; i++) {
        result.push_back(BASE58_CHARS[digits[digitslen - 1 - i]]);
    }
    
    return result;
}

// 计算WIF压缩格式
std::string private_key_to_wif_compressed(const BIGNUM* private_key) {
    std::vector<unsigned char> private_key_bytes(32);
    BN_bn2binpad(private_key, private_key_bytes.data(), 32);
    
    // 添加版本字节和压缩标志
    std::vector<unsigned char> wif_bytes;
    wif_bytes.push_back(0x80); // 主网版本字节
    wif_bytes.insert(wif_bytes.end(), private_key_bytes.begin(), private_key_bytes.end());
    wif_bytes.push_back(0x01); // 压缩标志
    
    // 计算校验和
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(wif_bytes.data(), wif_bytes.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    
    // 添加校验和
    wif_bytes.insert(wif_bytes.end(), hash2, hash2 + 4);
    
    return base58_encode(wif_bytes);
}

// 从私钥生成压缩格式比特币地址
std::string private_key_to_compressed_address(const BIGNUM* private_key) {
    // 创建EC_KEY
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) return "";
    
    // 设置私钥
    if (EC_KEY_set_private_key(ec_key, private_key) != 1) {
        EC_KEY_free(ec_key);
        return "";
    }
    
    // 计算公钥点
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* public_key_point = EC_POINT_new(group);
    if (!public_key_point) {
        EC_KEY_free(ec_key);
        return "";
    }
    
    if (EC_POINT_mul(group, public_key_point, private_key, nullptr, nullptr, nullptr) != 1) {
        EC_POINT_free(public_key_point);
        EC_KEY_free(ec_key);
        return "";
    }
    
    // 获取公钥点的坐标
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    
    if (EC_POINT_get_affine_coordinates(group, public_key_point, x, y, nullptr) != 1) {
        BN_free(x);
        BN_free(y);
        EC_POINT_free(public_key_point);
        EC_KEY_free(ec_key);
        return "";
    }
    
    // 转换为压缩公钥格式
    std::vector<unsigned char> public_key_compressed;
    public_key_compressed.push_back(BN_is_odd(y) ? 0x03 : 0x02);
    
    std::vector<unsigned char> x_bytes(32);
    BN_bn2binpad(x, x_bytes.data(), 32);
    public_key_compressed.insert(public_key_compressed.end(), x_bytes.begin(), x_bytes.end());
    
    // 计算SHA256
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(public_key_compressed.data(), public_key_compressed.size(), sha256_hash);
    
    // 计算RIPEMD160
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);
    
    // 添加版本字节
    std::vector<unsigned char> address_bytes;
    address_bytes.push_back(0x00); // 主网版本字节
    address_bytes.insert(address_bytes.end(), ripemd160_hash, ripemd160_hash + RIPEMD160_DIGEST_LENGTH);
    
    // 计算校验和
    unsigned char checksum1[SHA256_DIGEST_LENGTH];
    unsigned char checksum2[SHA256_DIGEST_LENGTH];
    SHA256(address_bytes.data(), address_bytes.size(), checksum1);
    SHA256(checksum1, SHA256_DIGEST_LENGTH, checksum2);
    
    // 添加校验和
    address_bytes.insert(address_bytes.end(), checksum2, checksum2 + 4);
    
    // Base58编码
    std::string address = base58_encode(address_bytes);
    
    // 清理内存
    BN_free(x);
    BN_free(y);
    EC_POINT_free(public_key_point);
    EC_KEY_free(ec_key);
    
    return address;
}

// 生成指定范围内的随机私钥
void generate_private_key_in_range(BIGNUM* result, const BIGNUM* min_key, const BIGNUM* max_key, BN_CTX* ctx) {
    BIGNUM* range = BN_new();
    BIGNUM* temp = BN_new();
    
    // 计算范围: range = max_key - min_key
    BN_sub(range, max_key, min_key);
    
    // 生成随机数
    BN_rand_range(temp, range);
    
    // 结果 = min_key + 随机数
    BN_add(result, min_key, temp);
    
    BN_free(range);
    BN_free(temp);
}

// 工作线程函数
void worker_thread(int thread_id, int total_threads, const BIGNUM* min_key, const BIGNUM* max_key) {
    // 创建OpenSSL BN上下文
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* private_key = BN_new();
    
    uint64_t local_keys_checked = 0;
    auto last_report_time = std::chrono::steady_clock::now();
    
    while (!found) {
        // 生成范围内的随机私钥
        generate_private_key_in_range(private_key, min_key, max_key, ctx);
        
        // 生成地址
        std::string address = private_key_to_compressed_address(private_key);
        local_keys_checked++;
        
        if (address == TARGET_ADDRESS) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "\n🎉 线程 " << thread_id << " 找到匹配的地址! 🎉" << std::endl;
            std::cout << "目标地址: " << TARGET_ADDRESS << std::endl;
            
            std::string wif = private_key_to_wif_compressed(private_key);
            std::cout << "WIF压缩格式私钥: " << wif << std::endl;
            
            char* hex_private_key = BN_bn2hex(private_key);
            std::cout << "私钥(十六进制): " << hex_private_key << std::endl;
            OPENSSL_free(hex_private_key);
            
            // 保存到文件
            std::ofstream file("found_key.txt");
            file << "目标地址: " << TARGET_ADDRESS << "\n";
            file << "WIF压缩格式私钥: " << wif << "\n";
            file << "私钥(十六进制): " << hex_private_key << "\n";
            file << "发现时间: " << std::chrono::system_clock::now() << "\n";
            file << "工作线程: " << thread_id << "\n";
            file.close();
            
            found = true;
            break;
        }
        
        // 定期更新计数器和报告进度
        auto current_time = std::chrono::steady_clock::now();
        if (current_time - last_report_time > std::chrono::seconds(5)) {
            keys_checked += local_keys_checked;
            local_keys_checked = 0;
            last_report_time = current_time;
        }
    }
    
    // 清理内存
    BN_free(private_key);
    BN_CTX_free(ctx);
    
    // 报告最终计数
    keys_checked += local_keys_checked;
}

// 进度监控函数
void progress_monitor(int total_threads) {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_keys_checked = 0;
    auto last_time = start_time;
    
    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto current_time = std::chrono::steady_clock::now();
        uint64_t current_keys_checked = keys_checked.load();
        double elapsed_seconds = std::chrono::duration<double>(current_time - start_time).count();
        
        // 计算速度
        double keys_per_second = current_keys_checked / elapsed_seconds;
        double instant_speed = (current_keys_checked - last_keys_checked) / 
                              std::chrono::duration<double>(current_time - last_time).count();
        
        std::cout << "\n=== 进度监控 ===" << std::endl;
        std::cout << "运行时间: " << std::fixed << std::setprecision(2) << elapsed_seconds << " 秒" << std::endl;
        std::cout << "总检查密钥数: " << current_keys_checked << std::endl;
        std::cout << "平均速度: " << std::fixed << std::setprecision(0) << keys_per_second << " 密钥/秒" << std::endl;
        std::cout << "瞬时速度: " << std::fixed << std::setprecision(0) << instant_speed << " 密钥/秒" << std::endl;
        std::cout << "搜索范围: 2^70 到 2^71" << std::endl;
        std::cout << "================\n" << std::endl;
        
        last_keys_checked = current_keys_checked;
        last_time = current_time;
    }
}

int main() {
    std::cout << "=== 高性能C++比特币私钥碰撞程序 ===" << std::endl;
    std::cout << "目标地址: " << TARGET_ADDRESS << std::endl;
    std::cout << "搜索范围: 2^70 到 2^71" << std::endl;
    std::cout << "密钥格式: 压缩格式" << std::endl;
    std::cout << "==================================" << std::endl;
    
    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();
    
    // 创建范围边界
    BIGNUM* min_key = BN_new();
    BIGNUM* max_key = BN_new();
    
    // 使用字符串初始化大数
    BN_dec2bn(&min_key, MIN_KEY_STR);
    BN_dec2bn(&max_key, MAX_KEY_STR);
    
    // 确定线程数
    int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4; // 默认4线程
    std::cout << "使用 " << num_threads << " 个线程" << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // 启动进度监控线程
    std::thread monitor_thread(progress_monitor, num_threads);
    
    // 启动工作线程
    std::vector<std::thread> worker_threads;
    for (int i = 0; i < num_threads; i++) {
        worker_threads.emplace_back(worker_thread, i, num_threads, min_key, max_key);
    }
    
    // 等待工作线程完成
    for (auto& thread : worker_threads) {
        thread.join();
    }
    
// 等待监控线程完成
    monitor_thread.join();
    
    auto end_time = std::chrono::steady_clock::now();
    double total_seconds = std::chrono::duration<double>(end_time - start_time).count();
    
    std::cout << "\n程序运行完成" << std::endl;
    std::cout << "总运行时间: " << total_seconds << " 秒" << std::endl;
    std::cout << "总检查密钥数: " << keys_checked.load() << std::endl;
    std::cout << "平均速度: " << keys_checked.load() / total_seconds << " 密钥/秒" << std::endl;
    
    // 清理内存
    BN_free(min_key);
    BN_free(max_key);
    
    // 清理OpenSSL
    EVP_cleanup();
    
    return 0;
}
