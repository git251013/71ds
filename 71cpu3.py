#!/usr/bin/env python3
"""
比特币私钥碰撞工具 - 多进程CPU优化版本
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
搜索范围: 2^70 到 2^71 (压缩格式私钥)
"""

import os
import sys
import time
import hashlib
import multiprocessing as mp
from multiprocessing import Pool, Manager, Value, Lock
import secrets
import base58
import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.numbertheory import inverse_mod
import threading

# 常量定义
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
START_RANGE = 2**70
END_RANGE = 2**71
CPU_COUNT = mp.cpu_count()
BATCH_SIZE = 1000  # 每批处理的密钥数量

class BitcoinKeyGenerator:
    def __init__(self):
        self.curve = SECP256k1
        self.G = self.curve.generator
        self.p = self.curve.curve.p()
        self.n = self.curve.order
        
    def private_key_to_compressed_wif(self, private_key_int):
        """将私钥整数转换为WIF压缩格式"""
        # 添加版本字节(0x80)和压缩标志(0x01)
        private_key_bytes = private_key_int.to_bytes(32, 'big')
        extended_key = b'\x80' + private_key_bytes + b'\x01'
        
        # 双重SHA256哈希
        first_sha = hashlib.sha256(extended_key).digest()
        checksum = hashlib.sha256(first_sha).digest()[:4]
        
        # Base58编码
        wif = base58.b58encode(extended_key + checksum)
        return wif.decode('utf-8')
    
    def private_key_to_compressed_address(self, private_key_int):
        """从私钥生成压缩格式比特币地址"""
        try:
            # 使用ecdsa库生成公钥
            private_key_bytes = private_key_int.to_bytes(32, 'big')
            sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=SECP256k1)
            vk = sk.get_verifying_key()
            
            # 压缩公钥格式
            public_key_bytes = vk.to_string("compressed")
            
            # SHA256哈希
            sha256_hash = hashlib.sha256(public_key_bytes).digest()
            
            # RIPEMD160哈希
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            
            # 添加版本字节 (0x00 用于主网)
            versioned_payload = b'\x00' + ripemd160_hash
            
            # 计算校验和
            checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
            
            # Base58编码
            binary_address = versioned_payload + checksum
            bitcoin_address = base58.b58encode(binary_address)
            
            return bitcoin_address.decode('utf-8')
            
        except Exception as e:
            return None

class OptimizedKeySearcher:
    def __init__(self, target_address, start_range, end_range):
        self.target_address = target_address
        self.start_range = start_range
        self.end_range = end_range
        self.range_size = end_range - start_range
        self.key_gen = BitcoinKeyGenerator()
        self.found_flag = Value('b', False)
        self.keys_tested = Value('Q', 0)  # 无符号长整型
        self.lock = Lock()
        
    def generate_secure_random_keys(self, count):
        """生成密码学安全的随机私钥"""
        keys = []
        for _ in range(count):
            # 在指定范围内生成随机私钥
            key_int = secrets.randbelow(self.range_size) + self.start_range
            keys.append(key_int)
        return keys
    
    def worker_process(self, process_id, results_queue):
        """工作进程函数"""
        print(f"进程 {process_id} 启动，搜索范围: {self.start_range} - {self.end_range}")
        
        keys_tested_local = 0
        start_time = time.time()
        
        while not self.found_flag.value:
            # 批量生成密钥以提高效率
            batch_keys = self.generate_secure_random_keys(BATCH_SIZE)
            
            for private_key_int in batch_keys:
                if self.found_flag.value:
                    break
                    
                try:
                    # 生成压缩地址
                    address = self.key_gen.private_key_to_compressed_address(private_key_int)
                    keys_tested_local += 1
                    
                    if keys_tested_local % 10000 == 0:
                        elapsed = time.time() - start_time
                        rate = keys_tested_local / elapsed if elapsed > 0 else 0
                        print(f"进程 {process_id}: 已测试 {keys_tested_local} 个密钥, 速率: {rate:.2f} 密钥/秒")
                    
                    if address and address == self.target_address:
                        print(f"\n*** 找到匹配的地址! ***")
                        print(f"目标地址: {self.target_address}")
                        print(f"找到的地址: {address}")
                        
                        # 获取WIF压缩格式私钥
                        wif_compressed = self.key_gen.private_key_to_compressed_wif(private_key_int)
                        print(f"WIF压缩私钥: {wif_compressed}")
                        print(f"私钥 (十进制): {private_key_int}")
                        print(f"私钥 (十六进制): {hex(private_key_int)}")
                        
                        # 保存结果到文件
                        with open("found_private_key.txt", "w") as f:
                            f.write(f"目标地址: {self.target_address}\n")
                            f.write(f"WIF压缩私钥: {wif_compressed}\n")
                            f.write(f"私钥 (十进制): {private_key_int}\n")
                            f.write(f"私钥 (十六进制): {hex(private_key_int)}\n")
                        
                        with self.lock:
                            self.found_flag.value = True
                            self.keys_tested.value += keys_tested_local
                        
                        results_queue.put({
                            'process_id': process_id,
                            'private_key': private_key_int,
                            'wif_compressed': wif_compressed,
                            'keys_tested': keys_tested_local,
                            'address': address
                        })
                        return
                        
                except Exception as e:
                    continue
            
            # 定期更新全局计数器
            if keys_tested_local % 1000 == 0:
                with self.lock:
                    self.keys_tested.value += 1000
        
        # 进程结束时的统计
        with self.lock:
            self.keys_tested.value += keys_tested_local % 1000
        
        print(f"进程 {process_id} 结束, 测试了 {keys_tested_local} 个密钥")

    def start_search(self, num_processes=None):
        """启动多进程搜索"""
        if num_processes is None:
            num_processes = CPU_COUNT
            
        print(f"开始搜索比特币私钥...")
        print(f"目标地址: {self.target_address}")
        print(f"搜索范围: {self.start_range} 到 {self.end_range}")
        print(f"使用进程数: {num_processes}")
        print(f"每批处理密钥数: {BATCH_SIZE}")
        print(f"总搜索空间: {self.range_size:,} 个密钥")
        print("-" * 60)
        
        start_time = time.time()
        
        # 创建进程池
        with Manager() as manager:
            results_queue = manager.Queue()
            processes = []
            
            # 启动工作进程
            for i in range(num_processes):
                p = mp.Process(target=self.worker_process, args=(i, results_queue))
                processes.append(p)
                p.start()
            
            # 监控进程
            try:
                while any(p.is_alive() for p in processes):
                    time.sleep(5)
                    elapsed = time.time() - start_time
                    total_tested = self.keys_tested.value
                    
                    if elapsed > 0:
                        rate = total_tested / elapsed
                        print(f"\r总进度: {total_tested:,} 密钥测试, "
                              f"速率: {rate:,.0f} 密钥/秒, "
                              f"运行时间: {elapsed:.1f}秒", end="")
                    
                    # 检查是否有结果
                    if not results_queue.empty():
                        result = results_queue.get()
                        print(f"\n\n*** 成功找到私钥! ***")
                        print(f"进程 {result['process_id']} 找到匹配")
                        print(f"WIF压缩私钥: {result['wif_compressed']}")
                        
                        # 终止所有进程
                        for p in processes:
                            if p.is_alive():
                                p.terminate()
                        break
                        
            except KeyboardInterrupt:
                print(f"\n用户中断搜索...")
                for p in processes:
                    if p.is_alive():
                        p.terminate()
            
            # 等待所有进程结束
            for p in processes:
                p.join()
            
            total_time = time.time() - start_time
            print(f"\n\n搜索结束!")
            print(f"总测试密钥数: {self.keys_tested.value:,}")
            print(f"总运行时间: {total_time:.2f} 秒")
            print(f"平均速率: {self.keys_tested.value/total_time:,.0f} 密钥/秒" if total_time > 0 else "N/A")

def main():
    """主函数"""
    print("比特币私钥碰撞工具 - 多进程优化版")
    print("=" * 60)
    
    # 初始化搜索器
    searcher = OptimizedKeySearcher(TARGET_ADDRESS, START_RANGE, END_RANGE)
    
    # 计算概率
    total_space = END_RANGE - START_RANGE
    print(f"搜索空间大小: {total_space:,} 个可能的私钥")
    print(f"成功概率: 约 {1/total_space:.10e}")
    print(f"注意: 这是一个极大的搜索空间，找到匹配密钥的概率极低")
    print("=" * 60)
    
    # 确认开始
    response = input("是否开始搜索? (y/N): ").lower().strip()
    if response not in ['y', 'yes']:
        print("搜索已取消")
        return
    
    # 启动搜索
    try:
        searcher.start_search()
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # 设置多进程启动方法
    if sys.platform.startswith('win'):
        mp.set_start_method('spawn')
    else:
        mp.set_start_method('fork')
    
    # 检查依赖
    try:
        import base58
        import ecdsa
        import secrets
    except ImportError as e:
        print(f"缺少依赖库: {e}")
        print("请安装所需库: pip install base58 ecdsa")
        sys.exit(1)
    
    main()
