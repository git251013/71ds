import hashlib
import base58
import os
import multiprocessing
import time
import secrets
import random
from multiprocessing import Process, Value, Lock

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# 范围定义 (2^70 到 2^71)
MIN_KEY = 2**70
MAX_KEY = 2**71

# secp256k1曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def mod_inverse(a, n=P):
    """扩展欧几里得算法求模逆"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        hm, lm = lm, nm
        high, low = low, new
    return lm % n

def elliptic_curve_add(point1, point2):
    """椭圆曲线点加法"""
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    
    x1, y1 = point1
    x2, y2 = point2
    
    if x1 == x2:
        if y1 != y2:
            return None  # 点互为逆元，结果为无穷远点
        else:
            # 点加倍
            s = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        # 点相加
        s = (y2 - y1) * mod_inverse(x2 - x1, P) % P
    
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    
    return (x3, y3)

def elliptic_curve_multiply(k, point):
    """椭圆曲线标量乘法"""
    if k == 0:
        return None
    if k == 1:
        return point
    
    # 使用二进制展开法
    result = None
    addend = point
    
    while k:
        if k & 1:
            result = elliptic_curve_add(result, addend)
        addend = elliptic_curve_add(addend, addend)
        k >>= 1
    
    return result

def private_key_to_wif_compressed(private_key_int):
    """将整数私钥转换为WIF压缩格式"""
    try:
        # 确保私钥在有效范围内
        if private_key_int <= 0 or private_key_int >= N:
            return None
            
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
    except Exception as e:
        return None

def private_key_to_compressed_address(private_key_int):
    """从私钥生成压缩格式比特币地址"""
    try:
        # 验证私钥范围
        if private_key_int <= 0 or private_key_int >= N:
            return None
        
        # 计算公钥点
        public_key_point = elliptic_curve_multiply(private_key_int, (Gx, Gy))
        if public_key_point is None:
            return None
            
        x, y = public_key_point
        
        # 压缩公钥格式 (02 或 03 + x坐标)
        if y % 2 == 0:
            compressed_public_key = b'\x02' + x.to_bytes(32, 'big')
        else:
            compressed_public_key = b'\x03' + x.to_bytes(32, 'big')
        
        # SHA256哈希
        sha256_hash = hashlib.sha256(compressed_public_key).digest()
        
        # RIPEMD160哈希
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
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
    except Exception as e:
        return None

def generate_valid_private_key():
    """生成有效的私钥"""
    while True:
        try:
            # 在指定范围内生成随机私钥
            private_key_int = secrets.randbelow(MAX_KEY - MIN_KEY) + MIN_KEY
            
            # 确保私钥在有效范围内
            if 1 <= private_key_int < N:
                return private_key_int
        except Exception:
            continue

def worker(worker_id, keys_checked_counter, found_flag, start_time, lock):
    """工作进程函数"""
    print(f"进程 {worker_id} 启动")
    
    keys_checked = 0
    batch_size = 100
    
    while not found_flag.value:
        batch_keys_checked = 0
        for _ in range(batch_size):
            if found_flag.value:
                break
                
            try:
                # 生成有效私钥
                private_key_int = generate_valid_private_key()
                
                # 生成压缩地址
                address = private_key_to_compressed_address(private_key_int)
                
                if address is None:
                    continue
                    
                batch_keys_checked += 1
                
                if address == TARGET_ADDRESS:
                    print(f"\n🎉 找到匹配的地址! 🎉")
                    print(f"目标地址: {TARGET_ADDRESS}")
                    wif = private_key_to_wif_compressed(private_key_int)
                    if wif:
                        print(f"WIF压缩格式私钥: {wif}")
                        print(f"私钥(十六进制): {format(private_key_int, '064x')}")
                        
                        # 保存到文件
                        with lock:
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
        if keys_checked % 1000 == 0:
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
    lock = Lock()
    
    # 启动监控进程
    monitor_process = Process(target=monitor_progress, 
                            args=(keys_checked_counter, found_flag, start_time))
    monitor_process.daemon = True
    monitor_process.start()
    
    # 启动工作进程
    processes = []
    for i in range(num_processes):
        p = Process(target=worker, 
                   args=(i, keys_checked_counter, found_flag, start_time, lock))
        processes.append(p)
        p.start()
        time.sleep(0.1)  # 避免所有进程同时启动
    
    # 等待所有进程完成
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()
    
    if found_flag.value:
        print("🎉 成功找到匹配的私钥！")
    else:
        print("未找到匹配的私钥")
    
    total_time = time.time() - start_time.value
    print(f"总运行时间: {total_time:.2f} 秒")
    print(f"总检查密钥数: {keys_checked_counter.value:,}")

if __name__ == "__main__":
    # 设置随机种子
    random.seed(os.urandom(32))
    main()
