import hashlib
import base58
import os
import multiprocessing
import time
import struct
from multiprocessing import Process, Value, Lock, Queue
import secrets

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# 范围定义 (2^70 到 2^71)
MIN_KEY = 2**70
MAX_KEY = 2**71
RANGE_SIZE = MAX_KEY - MIN_KEY

# secp256k1曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# 预计算表 - 存储基点G的2的幂次倍点
PRECOMPUTED_POINTS = []
PRECOMPUTED_POINTS_COUNT = 256  # 预计算256个点，覆盖256位私钥

def mod_inverse(a, n=P):
    """使用费马小定理求模逆（在质数模下更快）"""
    return pow(a, n-2, n)

def precompute_points():
    """预计算基点G的2的幂次倍点"""
    global PRECOMPUTED_POINTS
    if PRECOMPUTED_POINTS:
        return PRECOMPUTED_POINTS
    
    points = []
    x, y = Gx, Gy
    
    for i in range(PRECOMPUTED_POINTS_COUNT):
        points.append((x, y))
        # 点加倍
        s = (3 * x * x) * mod_inverse(2 * y, P) % P
        x_new = (s * s - 2 * x) % P
        y_new = (s * (x - x_new) - y) % P
        x, y = x_new, y_new
    
    PRECOMPUTED_POINTS = points
    return points

def fast_ec_multiply(k, precomputed_points):
    """使用预计算表快速计算椭圆曲线标量乘法"""
    result_x, result_y = None, None
    
    # 处理k的每一位
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            if result_x is None:
                # 第一次设置结果
                result_x, result_y = precomputed_points[i]
            else:
                # 点相加
                x1, y1 = result_x, result_y
                x2, y2 = precomputed_points[i]
                
                if x1 == x2:
                    if y1 == y2:
                        # 点加倍
                        s = (3 * x1 * x1) * mod_inverse(2 * y1, P) % P
                    else:
                        # 点互为逆元，结果为无穷远点
                        continue
                else:
                    # 点相加
                    s = (y2 - y1) * mod_inverse(x2 - x1, P) % P
                
                x3 = (s * s - x1 - x2) % P
                y3 = (s * (x1 - x3) - y1) % P
                result_x, result_y = x3, y3
    
    return result_x, result_y

def private_key_to_wif_compressed(private_key_int):
    """将整数私钥转换为WIF压缩格式"""
    try:
        # 转换为32字节的十六进制，前面补0
        private_key_bytes = private_key_int.to_bytes(32, 'big')
        
        # 添加版本字节（主网）和压缩标志
        version_private_key_compressed = b'\x80' + private_key_bytes + b'\x01'
        
        # 双重SHA256哈希
        first_sha = hashlib.sha256(version_private_key_compressed).digest()
        checksum = hashlib.sha256(first_sha).digest()[:4]
        
        # 组合并Base58编码
        final_key = version_private_key_compressed + checksum
        wif_compressed = base58.b58encode(final_key)
        
        return wif_compressed.decode('utf-8')
    except Exception:
        return None

def private_key_to_compressed_address_fast(private_key_int, precomputed_points):
    """使用预计算表快速生成压缩格式比特币地址"""
    try:
        # 使用预计算表计算公钥点
        x, y = fast_ec_multiply(private_key_int, precomputed_points)
        if x is None or y is None:
            return None
        
        # 压缩公钥格式 (02 或 03 + x坐标)
        compressed_public_key = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
        
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
        
        # 组合并Base58编码
        binary_address = version_ripemd160 + checksum
        bitcoin_address = base58.b58encode(binary_address)
        
        return bitcoin_address.decode('utf-8')
    except Exception:
        return None

def generate_private_key_batch(batch_size):
    """批量生成私钥，提高效率"""
    keys = []
    for _ in range(batch_size):
        # 在指定范围内生成随机私钥
        private_key_int = secrets.randbelow(RANGE_SIZE) + MIN_KEY
        # 确保私钥在有效范围内
        if 1 <= private_key_int < N:
            keys.append(private_key_int)
    return keys

def worker(worker_id, keys_checked_counter, found_flag, start_time, lock, progress_queue, precomputed_points):
    """工作进程函数 - 优化版本"""
    print(f"进程 {worker_id} 启动")
    
    keys_checked = 0
    batch_size = 1000  # 增加批次大小以提高效率
    last_report_time = time.time()
    
    while not found_flag.value:
        # 批量生成私钥
        private_keys = generate_private_key_batch(batch_size)
        
        for private_key_int in private_keys:
            if found_flag.value:
                break
                
            # 生成压缩地址
            address = private_key_to_compressed_address_fast(private_key_int, precomputed_points)
            
            if address is None:
                continue
                
            keys_checked += 1
            
            if address == TARGET_ADDRESS:
                print(f"\n🎉 进程 {worker_id} 找到匹配的地址! 🎉")
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
        
        # 更新计数器
        with keys_checked_counter.get_lock():
            keys_checked_counter.value += len(private_keys)
        
        # 定期报告进度
        current_time = time.time()
        if current_time - last_report_time > 5:  # 每5秒报告一次
            elapsed_time = current_time - start_time.value
            total_keys = keys_checked_counter.value
            keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
            
            progress_queue.put((worker_id, keys_checked, total_keys, keys_per_second))
            last_report_time = current_time

def progress_monitor(keys_checked_counter, found_flag, start_time, progress_queue, num_processes):
    """进度监控器 - 优化版本"""
    worker_progress = [0] * num_processes
    last_total = 0
    last_time = start_time.value
    
    while not found_flag.value:
        try:
            # 收集所有工作进程的进度
            while not progress_queue.empty():
                worker_id, keys_checked, total_keys, keys_per_second = progress_queue.get()
                worker_progress[worker_id] = keys_checked
            
            current_time = time.time()
            elapsed_time = current_time - start_time.value
            total_keys = keys_checked_counter.value
            
            # 计算瞬时速度
            time_diff = current_time - last_time
            keys_diff = total_keys - last_total
            instant_speed = keys_diff / time_diff if time_diff > 0 else 0
            
            if elapsed_time > 0 and total_keys > 0:
                print(f"\n=== 进度监控 ===")
                print(f"运行时间: {elapsed_time:.2f} 秒")
                print(f"总检查密钥数: {total_keys:,}")
                print(f"平均速度: {total_keys/elapsed_time:,.0f} 密钥/秒")
                print(f"瞬时速度: {instant_speed:,.0f} 密钥/秒")
                
                # 估算剩余时间
                keys_remaining = RANGE_SIZE - total_keys % RANGE_SIZE
                if instant_speed > 0:
                    eta_seconds = keys_remaining / instant_speed
                    eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
                    print(f"预估剩余时间: {eta_str}")
                
                # 显示各进程进度
                print("各进程进度:")
                for i in range(num_processes):
                    print(f"  进程 {i}: {worker_progress[i]:,}")
                print("================")
            
            last_total = total_keys
            last_time = current_time
            
            time.sleep(5)  # 每5秒更新一次
        except Exception as e:
            continue

def main():
    print("=== 优化版比特币私钥碰撞程序 ===")
    print(f"目标地址: {TARGET_ADDRESS}")
    print(f"搜索范围: 2^70 到 2^71")
    print(f"密钥格式: 压缩格式")
    print("=" * 50)
    
    # 预计算点表
    print("预计算基点倍数的点...")
    precomputed_points = precompute_points()
    print(f"预计算完成，共 {len(precomputed_points)} 个点")
    
    # 使用CPU核心数
    num_processes = multiprocessing.cpu_count()
    print(f"使用 {num_processes} 个进程")
    
    # 共享变量
    keys_checked_counter = Value('i', 0)
    found_flag = Value('i', 0)
    start_time = Value('d', time.time())
    lock = Lock()
    progress_queue = Queue()
    
    # 启动工作进程
    processes = []
    for i in range(num_processes):
        p = Process(target=worker, 
                   args=(i, keys_checked_counter, found_flag, start_time, lock, progress_queue, precomputed_points))
        processes.append(p)
        p.start()
        time.sleep(0.1)  # 避免所有进程同时启动
    
    # 启动监控进程
    monitor_process = Process(target=progress_monitor, 
                            args=(keys_checked_counter, found_flag, start_time, progress_queue, num_processes))
    monitor_process.daemon = True
    monitor_process.start()
    
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
    main()
