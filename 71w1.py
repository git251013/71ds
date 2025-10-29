import hashlib
import base58
import os
import multiprocessing
import time
import secrets
from multiprocessing import Process, Queue, Value

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# 范围定义 (2^70 到 2^71)
MIN_KEY = 2**70
MAX_KEY = 2**71

def private_key_to_wif_compressed(private_key_int):
    """将整数私钥转换为WIF压缩格式"""
    # 转换为32字节的十六进制，前面补0
    private_key_hex = format(private_key_int, '064x')
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # 添加版本字节（主网）
    version_private_key = b'\x80' + private_key_bytes
    
    # 添加压缩标志
    version_private_key_compressed = version_private_key + b'\x01'
    
    # 第一次SHA256
    first_sha = hashlib.sha256(version_private_key_compressed).digest()
    
    # 第二次SHA256
    second_sha = hashlib.sha256(first_sha).digest()
    
    # 取前4字节作为校验和
    checksum = second_sha[:4]
    
    # 组合
    final_key = version_private_key_compressed + checksum
    
    # Base58编码
    wif_compressed = base58.b58encode(final_key)
    
    return wif_compressed.decode('utf-8')

def private_key_to_compressed_address(private_key_int):
    """从私钥生成压缩格式比特币地址"""
    # 使用secp256k1曲线的参数
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    # 计算公钥点
    x = Gx
    y = Gy
    for bit in bin(private_key_int)[3:]:
        # 点加倍
        s = (3 * x * x * pow(2 * y, -1, p)) % p
        x3 = (s * s - 2 * x) % p
        y3 = (s * (x - x3) - y) % p
        x, y = x3, y3
        
        if bit == '1':
            # 点相加
            s = ((y - Gy) * pow(x - Gx, -1, p)) % p
            x3 = (s * s - Gx - x) % p
            y3 = (s * (Gx - x3) - Gy) % p
            x, y = x3, y3
    
    # 压缩公钥格式
    compressed_public_key = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
    
    # SHA256哈希
    sha256_hash = hashlib.sha256(compressed_public_key).digest()
    
    # RIPEMD160哈希
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # 添加版本字节（主网）
    version_ripemd160 = b'\x00' + ripemd160_hash
    
    # 计算校验和
    checksum_full = hashlib.sha256(hashlib.sha256(version_ripemd160).digest()).digest()
    checksum = checksum_full[:4]
    
    # 组合
    binary_address = version_ripemd160 + checksum
    
    # Base58编码
    bitcoin_address = base58.b58encode(binary_address)
    
    return bitcoin_address.decode('utf-8')

def worker(worker_id, keys_checked_counter, found_flag, start_time):
    """工作进程函数"""
    print(f"进程 {worker_id} 启动")
    
    keys_checked = 0
    batch_size = 1000
    
    while not found_flag.value:
        batch_keys_checked = 0
        for _ in range(batch_size):
            if found_flag.value:
                break
                
            # 在指定范围内生成随机私钥
            private_key_int = secrets.randbelow(MAX_KEY - MIN_KEY) + MIN_KEY
            
            try:
                # 生成压缩地址
                address = private_key_to_compressed_address(private_key_int)
                batch_keys_checked += 1
                
                if address == TARGET_ADDRESS:
                    print(f"\n🎉 找到匹配的地址! 🎉")
                    print(f"目标地址: {TARGET_ADDRESS}")
                    wif = private_key_to_wif_compressed(private_key_int)
                    print(f"WIF压缩格式私钥: {wif}")
                    print(f"私钥(十六进制): {format(private_key_int, '064x')}")
                    
                    # 保存到文件
                    with open(f"found_key_{worker_id}.txt", "w") as f:
                        f.write(f"目标地址: {TARGET_ADDRESS}\n")
                        f.write(f"WIF压缩格式私钥: {wif}\n")
                        f.write(f"私钥(十六进制): {format(private_key_int, '064x')}\n")
                        f.write(f"发现时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"工作进程: {worker_id}\n")
                    
                    found_flag.value = 1
                    return
                    
            except Exception as e:
                continue
        
        # 更新计数器
        with keys_checked_counter.get_lock():
            keys_checked_counter.value += batch_keys_checked
        keys_checked += batch_keys_checked
        
        # 每处理一定数量后显示进度
        if keys_checked % 10000 == 0:
            elapsed_time = time.time() - start_time.value
            total_keys = keys_checked_counter.value
            keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
            
            print(f"进程 {worker_id}: 已检查 {keys_checked:,} 个密钥, "
                  f"总计: {total_keys:,}, "
                  f"速度: {keys_per_second:,.0f} 密钥/秒")

def monitor_progress(keys_checked_counter, found_flag, start_time):
    """监控进度"""
    while not found_flag.value:
        time.sleep(10)
        elapsed_time = time.time() - start_time.value
        total_keys = keys_checked_counter.value
        keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
        
        print(f"\n=== 进度监控 ===")
        print(f"运行时间: {elapsed_time:.2f} 秒")
        print(f"总检查密钥数: {total_keys:,}")
        print(f"平均速度: {keys_per_second:,.0f} 密钥/秒")
        print(f"搜索范围: 2^70 到 2^71")
        print("================\n")

def main():
    print("=== 比特币私钥碰撞程序 ===")
    print(f"目标地址: {TARGET_ADDRESS}")
    print(f"搜索范围: 2^70 到 2^71")
    print(f"密钥格式: 压缩格式")
    print("=" * 40)
    
    # 使用CPU核心数
    num_processes = multiprocessing.cpu_count()
    print(f"使用 {num_processes} 个进程")
    
    # 共享变量
    keys_checked_counter = Value('i', 0)
    found_flag = Value('i', 0)
    start_time = Value('d', time.time())
    
    # 启动监控进程
    monitor_process = Process(target=monitor_progress, 
                            args=(keys_checked_counter, found_flag, start_time))
    monitor_process.daemon = True
    monitor_process.start()
    
    # 启动工作进程
    processes = []
    for i in range(num_processes):
        p = Process(target=worker, 
                   args=(i, keys_checked_counter, found_flag, start_time))
        processes.append(p)
        p.start()
    
    # 等待所有进程完成
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        for p in processes:
            p.terminate()
    
    if found_flag.value:
        print("🎉 成功找到匹配的私钥！")
    else:
        print("未找到匹配的私钥")
    
    total_time = time.time() - start_time.value
    print(f"总运行时间: {total_time:.2f} 秒")
    print(f"总检查密钥数: {keys_checked_counter.value:,}")

if __name__ == "__main__":
    # 设置随机种子
    secrets.SystemRandom().seed(os.urandom(32))
    main()
