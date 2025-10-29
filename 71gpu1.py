import hashlib
import base58
import os
import time
import secrets
import random
import multiprocessing
import ctypes
from multiprocessing import Process, Value, Lock
import subprocess
import numpy as np

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

# 加载CUDA共享库
try:
    cuda_lib = ctypes.CDLL('./cuda_secp256k1.so')
    
    # 定义函数原型
    cuda_lib.gpu_batch_compute_public_keys.argtypes = [
        ctypes.POINTER(ctypes.c_ulonglong),  # private_keys
        ctypes.c_int,                        # batch_size
        ctypes.POINTER(ctypes.c_ulonglong),  # public_keys_x
        ctypes.POINTER(ctypes.c_ulonglong),  # public_keys_y
        ctypes.c_int                         # gpu_id
    ]
    cuda_lib.gpu_batch_compute_public_keys.restype = ctypes.c_int
    
    cuda_lib.get_gpu_count.argtypes = []
    cuda_lib.get_gpu_count.restype = ctypes.c_int
    
    CUDA_AVAILABLE = True
    print(f"CUDA库加载成功，检测到 {cuda_lib.get_gpu_count()} 个GPU")
except Exception as e:
    print(f"CUDA库加载失败: {e}")
    CUDA_AVAILABLE = False

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

def public_key_to_compressed_address(public_key_x, public_key_y):
    """从公钥坐标生成压缩格式比特币地址"""
    try:
        # 压缩公钥格式 (02 或 03 + x坐标)
        if public_key_y % 2 == 0:
            compressed_public_key = b'\x02' + public_key_x.to_bytes(32, 'big')
        else:
            compressed_public_key = b'\x03' + public_key_x.to_bytes(32, 'big')
        
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

def generate_batch_private_keys(batch_size):
    """生成一批有效的私钥"""
    private_keys = []
    for _ in range(batch_size):
        while True:
            try:
                # 在指定范围内生成随机私钥
                private_key_int = secrets.randbelow(MAX_KEY - MIN_KEY) + MIN_KEY
                
                # 确保私钥在有效范围内
                if 1 <= private_key_int < N:
                    private_keys.append(private_key_int)
                    break
            except Exception:
                continue
    return private_keys

def gpu_process_batch(worker_id, batch_size, found_flag, keys_checked_counter):
    """使用GPU处理一批私钥"""
    if not CUDA_AVAILABLE:
        return False, None
    
    try:
        # 生成私钥
        private_keys = generate_batch_private_keys(batch_size)
        
        # 转换为C类型数组
        private_keys_c = (ctypes.c_ulonglong * batch_size)()
        public_keys_x_c = (ctypes.c_ulonglong * batch_size)()
        public_keys_y_c = (ctypes.c_ulonglong * batch_size)()
        
        for i, key in enumerate(private_keys):
            private_keys_c[i] = key
        
        # 调用CUDA函数
        result = cuda_lib.gpu_batch_compute_public_keys(
            private_keys_c, batch_size, public_keys_x_c, public_keys_y_c, worker_id
        )
        
        if result != 0:
            print(f"GPU进程 {worker_id}: CUDA计算错误")
            return False, None
        
        # 检查每个地址
        for i in range(batch_size):
            if found_flag.value:
                break
                
            public_key_x = public_keys_x_c[i]
            public_key_y = public_keys_y_c[i]
            
            # 跳过无效的公钥点
            if public_key_x == 0 and public_key_y == 0:
                continue
            
            address = public_key_to_compressed_address(public_key_x, public_key_y)
            
            if address and address == TARGET_ADDRESS:
                return True, private_keys[i]
            
            keys_checked_counter.value += 1
        
        return False, None
        
    except Exception as e:
        print(f"GPU进程 {worker_id} 错误: {e}")
        return False, None

def worker_gpu(worker_id, keys_checked_counter, found_flag, start_time, lock):
    """GPU工作进程函数"""
    print(f"GPU进程 {worker_id} 启动")
    
    batch_size = 10000  # 每批处理的私钥数量
    
    while not found_flag.value:
        found, private_key = gpu_process_batch(worker_id, batch_size, found_flag, keys_checked_counter)
        
        if found:
            print(f"\n🎉 GPU进程 {worker_id} 找到匹配的地址! 🎉")
            print(f"目标地址: {TARGET_ADDRESS}")
            wif = private_key_to_wif_compressed(private_key)
            if wif:
                print(f"WIF压缩格式私钥: {wif}")
                print(f"私钥(十六进制): {format(private_key, '064x')}")
                
                # 保存到文件
                with lock:
                    with open(f"found_key_gpu_{worker_id}.txt", "w") as f:
                        f.write(f"目标地址: {TARGET_ADDRESS}\n")
                        f.write(f"WIF压缩格式私钥: {wif}\n")
                        f.write(f"私钥(十六进制): {format(private_key, '064x')}\n")
                        f.write(f"发现时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"工作进程: {worker_id}\n")
                        f.write(f"使用设备: GPU\n")
                
                found_flag.value = 1
                return
        
        # 定期显示进度
        current_count = keys_checked_counter.value
        if current_count % 100000 == 0:
            elapsed_time = time.time() - start_time.value
            keys_per_second = current_count / elapsed_time if elapsed_time > 0 else 0
            
            print(f"GPU进程 {worker_id}: 已检查 {current_count:,} 个密钥, "
                  f"速度: {keys_per_second:,.0f} 密钥/秒")

def monitor_progress(keys_checked_counter, found_flag, start_time):
    """监控进度"""
    while not found_flag.value:
        time.sleep(10)
        elapsed_time = time.time() - start_time.value
        total_keys = keys_checked_counter.value
        keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
        
        print(f"\n=== GPU进度监控 ===")
        print(f"运行时间: {elapsed_time:.2f} 秒")
        print(f"总检查密钥数: {total_keys:,}")
        print(f"平均速度: {keys_per_second:,.0f} 密钥/秒")
        print(f"搜索范围: 2^70 到 2^71")
        print(f"使用设备: GPU")
        print("==================\n")

def main():
    print("=== 比特币私钥碰撞程序 (GPU CUDA版本) ===")
    print(f"目标地址: {TARGET_ADDRESS}")
    print(f"搜索范围: 2^70 到 2^71")
    print(f"密钥格式: 压缩格式")
    
    if not CUDA_AVAILABLE:
        print("错误: CUDA不可用，请确保CUDA库已正确编译")
        return
    
    # 编译CUDA代码
    print("编译CUDA代码...")
    try:
        subprocess.run(["nvcc", "-shared", "-o", "cuda_secp256k1.so", 
                       "-Xcompiler", "-fPIC", "cuda_secp256k1.cu", 
                       "-arch=sm_60"], check=True)
        print("CUDA代码编译成功")
    except Exception as e:
        print(f"CUDA编译失败: {e}")
        return
    
    # 获取GPU数量
    gpu_count = cuda_lib.get_gpu_count()
    print(f"检测到 {gpu_count} 个GPU设备")
    
    # 使用GPU数量
    num_processes = min(gpu_count, multiprocessing.cpu_count())
    print(f"使用 {num_processes} 个进程")
    print("=" * 50)
    
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
    
    # 启动GPU工作进程
    processes = []
    for i in range(num_processes):
        p = Process(target=worker_gpu, 
                   args=(i, keys_checked_counter, found_flag, start_time, lock))
        processes.append(p)
        p.start()
        time.sleep(1)  # 避免所有进程同时启动
    
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
