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

// secp256k1曲线的阶（n）
const char* SECP256K1_ORDER_STR = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Base58字符集
const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// 全局变量
std::atomic<bool> found(false);
std::atomic<uint64_t> keys_checked(0);
std::mutex output_mutex;

// Base58编码函数
std::string base58_encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";
    
    // 计算前导零的数量
    size_t zero_count = 0;
    while (zero_count < data.size() && data[zero_count] == 0) {
        zero_count++;
    }
    
    // 转换为Base58
    std::vector<unsigned char> digits((data.size() - zero_count) * 138 / 100 + 1);
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
    
    // 构建结果字符串
    std::string result;
    result.reserve(zero_count + digitslen);
    
    // 添加前导零
    for (size_t i = 0; i < zero_count; i++) {
        result.push_back(BASE58_CHARS[0]);
    }
    
    // 添加Base58数字
    for (size_t i = 0; i < digitslen; i++) {
        result.push_back(BASE58_CHARS[digits[digitslen - 1 - i]]);
    }
    
    return result;
}

// 验证私钥是否有效（在1到n-1之间）
bool is_valid_private_key(const BIGNUM* private_key, const BIGNUM* secp256k1_order) {
    if (BN_is_zero(private_key)) {
        return false;
    }
    
    if (BN_cmp(private_key, secp256k1_order) >= 0) {
        return false;
    }
    
    return true;
}

// 计算WIF压缩格式
std::string private_key_to_wif_compressed(const BIGNUM* private_key) {
    if (!private_key) return "";
    
    // 将私钥转换为32字节
    std::vector<unsigned char> private_key_bytes(32);
    if (BN_bn2binpad(private_key, private_key_bytes.data(), 32) != 32) {
        return "";
    }
    
    // 添加版本字节和压缩标志
    std::vector<unsigned char> wif_bytes;
    wif_bytes.reserve(1 + 32 + 1 + 4); // 版本 + 私钥 + 压缩标志 + 校验和
    
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
std::string private_key_to_compressed_address(const BIGNUM* private_key, const BIGNUM* secp256k1_order) {
    if (!private_key || !is_valid_private_key(private_key, secp256k1_order)) {
        return "";
    }
    
    EC_KEY* ec_key = nullptr;
    EC_POINT* public_key_point = nullptr;
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    
    std::string result;
    
    do {
        // 创建EC_KEY
        ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ec_key) break;
        
        // 设置私钥
        if (EC_KEY_set_private_key(ec_key, private_key) != 1) break;
        
        // 计算公钥点
        const EC_GROUP* group = EC_KEY_get0_group(ec_key);
        public_key_point = EC_POINT_new(group);
        if (!public_key_point) break;
        
        if (EC_POINT_mul(group, public_key_point, private_key, nullptr, nullptr, nullptr) != 1) break;
        
        // 获取公钥点的坐标
        x = BN_new();
        y = BN_new();
        if (!x || !y) break;
        
        if (EC_POINT_get_affine_coordinates(group, public_key_point, x, y, nullptr) != 1) break;
        
        // 转换为压缩公钥格式
        std::vector<unsigned char> public_key_compressed;
        public_key_compressed.reserve(33);
        
        // 判断y坐标的奇偶性
        int y_parity = BN_is_odd(y) ? 1 : 0;
        public_key_compressed.push_back(0x02 + y_parity);
        
        std::vector<unsigned char> x_bytes(32);
        if (BN_bn2binpad(x, x_bytes.data(), 32) != 32) break;
        public_key_compressed.insert(public_key_compressed.end(), x_bytes.begin(), x_bytes.end());
        
        // 计算SHA256
        unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
        SHA256(public_key_compressed.data(), public_key_compressed.size(), sha256_hash);
        
        // 计算RIPEMD160
        unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
        RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);
        
        // 添加版本字节
        std::vector<unsigned char> address_bytes;
        address_bytes.reserve(1 + RIPEMD160_DIGEST_LENGTH + 4);
        
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
        result = base58_encode(address_bytes);
    } while (false);
    
    // 清理内存
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (public_key_point) EC_POINT_free(public_key_point);
    if (ec_key) EC_KEY_free(ec_key);
    
    return result;
}

// 生成指定范围内的有效私钥
bool generate_valid_private_key(BIGNUM* result, const BIGNUM* min_key, const BIGNUM* max_key, 
                               const BIGNUM* secp256k1_order, BN_CTX* ctx) {
    if (!result || !min_key || !max_key || !secp256k1_order || !ctx) {
        return false;
    }
    
    BIGNUM* range = BN_CTX_get(ctx);
    BIGNUM* temp = BN_CTX_get(ctx);
    
    if (!range || !temp) {
        return false;
    }
    
    // 计算范围: range = max_key - min_key
    if (BN_sub(range, max_key, min_key) != 1) {
        return false;
    }
    
    // 确保范围是正数
    if (BN_is_zero(range) || BN_is_negative(range)) {
        return false;
    }
    
    // 生成范围内的随机数
    if (BN_rand_range(temp, range) != 1) {
        return false;
    }
    
    // 结果 = min_key + 随机数
    if (BN_add(result, min_key, temp) != 1) {
        return false;
    }
    
    // 确保私钥在有效范围内
    if (!is_valid_private_key(result, secp256k1_order)) {
        return false;
    }
    
    return true;
}

// 工作线程函数
void worker_thread(int thread_id, const BIGNUM* min_key, const BIGNUM* max_key, 
                  const BIGNUM* secp256k1_order) {
    std::cout << "线程 " << thread_id << " 启动" << std::endl;
    
    // 创建OpenSSL BN上下文
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        std::cerr << "线程 " << thread_id << " 无法创建BN_CTX" << std::endl;
        return;
    }
    
    BIGNUM* private_key = BN_new();
    if (!private_key) {
        std::cerr << "线程 " << thread_id << " 无法创建BIGNUM" << std::endl;
        BN_CTX_free(ctx);
        return;
    }
    
    uint64_t local_keys_checked = 0;
    auto last_report_time = std::chrono::steady_clock::now();
    
    while (!found) {
        // 生成范围内的有效私钥
        if (!generate_valid_private_key(private_key, min_key, max_key, secp256k1_order, ctx)) {
            continue; // 如果生成失败，继续尝试
        }
        
        // 生成地址
        std::string address = private_key_to_compressed_address(private_key, secp256k1_order);
        if (address.empty()) {
            continue; // 如果地址生成失败，继续尝试
        }
        
        local_keys_checked++;
        
        if (address == TARGET_ADDRESS) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "\n🎉 线程 " << thread_id << " 找到匹配的地址! 🎉" << std::endl;
            std::cout << "目标地址: " << TARGET_ADDRESS << std::endl;
            
            std::string wif = private_key_to_wif_compressed(private_key);
            if (!wif.empty()) {
                std::cout << "WIF压缩格式私钥: " << wif << std::endl;
                
                char* hex_private_key = BN_bn2hex(private_key);
                if (hex_private_key) {
                    std::cout << "私钥(十六进制): " << hex_private_key << std::endl;
                    
                    // 保存到文件
                    std::ofstream file("found_key.txt");
                    if (file.is_open()) {
                        auto now = std::chrono::system_clock::now();
                        auto time_t = std::chrono::system_clock::to_time_t(now);
                        
                        file << "目标地址: " << TARGET_ADDRESS << "\n";
                        file << "WIF压缩格式私钥: " << wif << "\n";
                        file << "私钥(十六进制): " << hex_private_key << "\n";
                        file << "发现时间: " << std::ctime(&time_t);
                        file << "工作线程: " << thread_id << "\n";
                        file.close();
                    }
                    
                    OPENSSL_free(hex_private_key);
                }
            }
            
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
    std::cout << "线程 " << thread_id << " 退出" << std::endl;
}

// 进度监控函数
void progress_monitor() {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_keys_checked = 0;
    auto last_time = start_time;
    
    while (!found) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto current_time = std::chrono::steady_clock::now();
        uint64_t current_keys_checked = keys_checked.load();
        double elapsed_seconds = std::chrono::duration<double>(current_time - start_time).count();
        
        // 计算速度
        double keys_per_second = 0;
        double instant_speed = 0;
        
        if (elapsed_seconds > 0) {
            keys_per_second = current_keys_checked / elapsed_seconds;
        }
        
        double time_diff = std::chrono::duration<double>(current_time - last_time).count();
        if (time_diff > 0) {
            instant_speed = (current_keys_checked - last_keys_checked) / time_diff;
        }
        
        std::cout << "\n=== 进度监控 ===" << std::endl;
        std::cout << "运行时间: " << std::fixed << std::setprecision(2) << elapsed_seconds << " 秒" << std::endl;
        std::cout << "总检查密钥数: " << current_keys_checked << std::endl;
        
        if (keys_per_second > 0) {
            std::cout << "平均速度: " << std::fixed << std::setprecision(0) << keys_per_second << " 密钥/秒" << std::endl;
        }
        
        if (instant_speed > 0) {
            std::cout << "瞬时速度: " << std::fixed << std::setprecision(0) << instant_speed << " 密钥/秒" << std::endl;
        }
        
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
    
    // 创建secp256k1曲线的阶
    BIGNUM* secp256k1_order = BN_new();
    if (!secp256k1_order || BN_hex2bn(&secp256k1_order, SECP256K1_ORDER_STR) == 0) {
        std::cerr << "错误: 无法创建secp256k1曲线的阶" << std::endl;
        return 1;
    }
    
    // 创建搜索范围
    BIGNUM* min_key = BN_new();
    BIGNUM* max_key = BN_new();
    BIGNUM* two = BN_new();
    BIGNUM* temp = BN_new();
    
    if (!min_key || !max_key || !two || !temp) {
        std::cerr << "错误: 无法创建BIGNUM" << std::endl;
        BN_free(secp256k1_order);
        if (min_key) BN_free(min_key);
        if (max_key) BN_free(max_key);
        if (two) BN_free(two);
        if (temp) BN_free(temp);
        return 1;
    }
    
    // 设置值: two = 2
    BN_set_word(two, 2);
    
    // 计算min_key = 2^70
    BN_set_word(temp, 70);
    BN_exp(min_key, two, temp, BN_CTX_new());
    
    // 计算max_key = 2^71
    BN_set_word(temp, 71);
    BN_exp(max_key, two, temp, BN_CTX_new());
    
    // 验证范围
    if (BN_cmp(min_key, max_key) >= 0) {
        std::cerr << "错误: 无效的范围 (min >= max)" << std::endl;
        BN_free(secp256k1_order);
        BN_free(min_key);
        BN_free(max_key);
        BN_free(two);
        BN_free(temp);
        return 1;
    }
    
    // 确定线程数
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) {
        num_threads = 4; // 默认4线程
        std::cout << "警告: 无法检测CPU核心数，使用默认 " << num_threads << " 个线程" << std::endl;
    } else {
        std::cout << "检测到 " << num_threads << " 个CPU核心" << std::endl;
    }
    
    // 限制线程数，避免创建过多线程
    if (num_threads > 16) {
        num_threads = 16;
        std::cout << "警告: 线程数限制为 " << num_threads << " 个" << std::endl;
    }
    
    std::cout << "使用 " << num_threads << " 个线程" << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // 启动进度监控线程
    std::thread monitor_thread(progress_monitor);
    
    // 启动工作线程
    std::vector<std::thread> worker_threads;
    for (unsigned int i = 0; i < num_threads; i++) {
        worker_threads.emplace_back(worker_thread, i, min_key, max_key, secp256k1_order);
        // 短暂延迟，避免所有线程同时启动
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // 等待工作线程完成
    for (auto& thread : worker_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    // 等待监控线程完成
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    double total_seconds = std::chrono::duration<double>(end_time - start_time).count();
    
    std::cout << "\n程序运行完成" << std::endl;
    std::cout << "总运行时间: " << total_seconds << " 秒" << std::endl;
    std::cout << "总检查密钥数: " << keys_checked.load() << std::endl;
    
    if (total_seconds > 0) {
        std::cout << "平均速度: " << keys_checked.load() / total_seconds << " 密钥/秒" << std::endl;
    }
    
    // 清理内存
    BN_free(secp256k1_order);
    BN_free(min_key);
    BN_free(max_key);
    BN_free(two);
    BN_free(temp);
    
    // 清理OpenSSL
    EVP_cleanup();
    
    return 0;
}
