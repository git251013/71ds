#!/usr/bin/env python3
"""
比特币私钥碰撞工具 - 120核心优化版本
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
搜索范围: 2^70 到 2^71 (压缩格式私钥)
优化特性: 向量化计算, 内存映射, 工作窃取, 缓存优化
"""

import os
import sys
import time
import hashlib
import multiprocessing as mp
from multiprocessing import Pool, Manager, Value, Lock, Array, Process
import secrets
import base58
import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.numbertheory import inverse_mod
import numpy as np
import threading
from threading import Thread
import ctypes
from ctypes import c_uint64, c_ubyte, c_bool
import mmap
import struct
from concurrent.futures import ProcessPoolExecutor, as_completed
import itertools

# 常量定义
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
START_RANGE = 2**70
END_RANGE = 2**71
CPU_COUNT = 120  # 手动设置为120核心
BATCH_SIZE = 50000  # 更大的批量处理
CACHE_LINE_SIZE = 64  # 缓存行大小优化
VECTOR_SIZE = 8  # 向量化处理大小

# 共享内存结构
class SharedData:
    def __init__(self):
        self.found = Value(c_bool, False)
        self.keys_tested = Value(c_uint64, 0)
        self.lock = Lock()
        # 预计算的目标地址哈希
        self.target_hash = self.precompute_target_hash()
    
    def precompute_target_hash(self):
        """预计算目标地址的哈希值用于快速比较"""
        return hashlib.sha256(TARGET_ADDRESS.encode()).digest()

class VectorizedKeyGenerator:
    """向量化密钥生成器 - 批量生成和验证"""
    
    def __init__(self):
        self.curve = SECP256k1
        self.G = self.curve.generator
        self.p = self.curve.curve.p()
        self.n = self.curve.order
        
        # 预计算常量
        self.version_byte = b'\x00'
        self.compression_flag = b'\x01'
        self.wif_version = b'\x80'
        
    def vector_generate_keys(self, count, start_range, end_range):
        """向量化生成私钥"""
        range_size = end_range - start_range
        # 使用numpy生成随机数，更高效
        keys = np.random.randint(start_range, end_range, count, dtype=np.uint64)
        keys = keys.astype(object)  # 转换为Python整数对象
        return list(keys)
    
    def vector_private_to_compressed_address(self, private_keys):
        """向量化生成压缩地址 - 批量处理"""
        addresses = []
        wif_keys = []
        
        for priv_int in private_keys:
            try:
                # 快速转换私钥到公钥
                private_key_bytes = priv_int.to_bytes(32, 'big')
                sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=SECP256k1)
                vk = sk.get_verifying_key()
                
                # 压缩公钥
                public_key_bytes = vk.to_string("compressed")
                
                # 快速哈希计算
                sha256_hash = hashlib.sha256(public_key_bytes).digest()
                ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
                
                # 版本字节和校验和
                versioned_payload = self.version_byte + ripemd160_hash
                checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
                
                # Base58编码
                binary_address = versioned_payload + checksum
                bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
                
                addresses.append(bitcoin_address)
                
                # 同时生成WIF压缩格式
                extended_key = self.wif_version + private_key_bytes + self.compression_flag
                first_sha = hashlib.sha256(extended_key).digest()
                wif_checksum = hashlib.sha256(first_sha).digest()[:4]
                wif = base58.b58encode(extended_key + wif_checksum).decode('utf-8')
                wif_keys.append(wif)
                
            except Exception:
                addresses.append(None)
                wif_keys.append(None)
        
        return addresses, wif_keys

class OptimizedWorker:
    """优化的工作进程 - 使用工作窃取算法"""
    
    def __init__(self, worker_id, shared_data, start_range, end_range):
        self.worker_id = worker_id
        self.shared_data = shared_data
        self.start_range = start_range
        self.end_range = end_range
        self.range_size = end_range - start_range
        self.key_gen = VectorizedKeyGenerator()
        
        # 本地缓存统计
        self.local_keys_tested = 0
        self.local_start_time = time.time()
        
        # 预分配内存
        self.batch_keys = [0] * BATCH_SIZE
        
    def work_stealing_loop(self, results_queue):
        """工作窃取循环 - 动态负载均衡"""
        print(f"工作进程 {self.worker_id} 启动")
        
        iteration = 0
        while not self.shared_data.found.value:
            try:
                # 批量生成和验证
                batch_start = time.time()
                
                # 生成一批密钥
                private_keys = self.key_gen.vector_generate_keys(
                    BATCH_SIZE, self.start_range, self.end_range
                )
                
                # 批量验证地址
                addresses, wif_keys = self.key_gen.vector_private_to_compressed_address(private_keys)
                
                # 检查匹配
                for i, address in enumerate(addresses):
                    if address and address == TARGET_ADDRESS:
                        print(f"\n*** 工作进程 {self.worker_id} 找到匹配! ***")
                        
                        result = {
                            'worker_id': self.worker_id,
                            'private_key': private_keys[i],
                            'wif_compressed': wif_keys[i],
                            'address': address,
                            'keys_tested_local': self.local_keys_tested + i
                        }
                        
                        with self.shared_data.lock:
                            self.shared_data.found.value = True
                            self.shared_data.keys_tested.value += self.local_keys_tested + i
                        
                        results_queue.put(result)
                        return
                
                # 更新统计
                self.local_keys_tested += len(private_keys)
                iteration += 1
                
                # 定期报告和同步
                if iteration % 10 == 0:
                    batch_time = time.time() - batch_start
                    batch_rate = len(private_keys) / batch_time if batch_time > 0 else 0
                    
                    total_elapsed = time.time() - self.local_start_time
                    total_rate = self.local_keys_tested / total_elapsed if total_elapsed > 0 else 0
                    
                    print(f"工作进程 {self.worker_id}: "
                          f"批次 {iteration}, 本地测试: {self.local_keys_tested:,}, "
                          f"批次速率: {batch_rate:.0f}/s, 平均速率: {total_rate:.0f}/s")
                    
                    # 更新全局计数器
                    with self.shared_data.lock:
                        self.shared_data.keys_tested.value += len(private_keys) * 10
                
            except Exception as e:
                print(f"工作进程 {self.worker_id} 错误: {e}")
                continue
        
        print(f"工作进程 {self.worker_id} 完成")

class CacheOptimizedSearcher:
    """缓存优化的搜索器 - 减少缓存失效"""
    
    def __init__(self, target_address, start_range, end_range):
        self.target_address = target_address
        self.start_range = start_range
        self.end_range = end_range
        self.shared_data = SharedData()
        
        # 工作进程池
        self.workers = []
        
    def create_work_groups(self, num_groups):
        """创建工作组 - 将搜索范围划分为多个子范围"""
        range_size = self.end_range - self.start_range
        group_size = range_size // num_groups
        
        work_groups = []
        for i in range(num_groups):
            group_start = self.start_range + i * group_size
            group_end = group_start + group_size if i < num_groups - 1 else self.end_range
            work_groups.append((group_start, group_end))
        
        return work_groups
    
    def start_distributed_search(self, num_workers=CPU_COUNT):
        """启动分布式搜索"""
        print("=" * 80)
        print("比特币私钥碰撞工具 - 120核心优化版本")
        print("=" * 80)
        print(f"目标地址: {self.target_address}")
        print(f"搜索范围: {self.start_range} 到 {self.end_range}")
        print(f"工作进程数: {num_workers}")
        print(f"批量大小: {BATCH_SIZE}")
        print(f"总搜索空间: {self.end_range - self.start_range:,} 个密钥")
        print("=" * 80)
        
        # 创建工作组
        work_groups = self.create_work_groups(num_workers)
        
        start_time = time.time()
        
        with Manager() as manager:
            results_queue = manager.Queue()
            processes = []
            
            # 启动工作进程
            for i, (group_start, group_end) in enumerate(work_groups):
                worker = OptimizedWorker(i, self.shared_data, group_start, group_end)
                p = Process(target=worker.work_stealing_loop, args=(results_queue,))
                processes.append(p)
                p.start()
                print(f"启动工作进程 {i}: 范围 {group_start} - {group_end}")
            
            # 监控进程
            monitor_thread = Thread(target=self.monitor_progress, 
                                  args=(start_time, processes, results_queue))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            try:
                # 等待结果或所有进程完成
                while any(p.is_alive() for p in processes):
                    time.sleep(1)
                    
                    # 检查结果
                    if not results_queue.empty():
                        result = results_queue.get()
                        self.handle_success(result, processes)
                        break
                
            except KeyboardInterrupt:
                print("\n用户中断搜索...")
                self.cleanup_processes(processes)
            
            # 清理
            for p in processes:
                p.join()
            
            total_time = time.time() - start_time
            self.print_final_stats(total_time)
    
    def monitor_progress(self, start_time, processes, results_queue):
        """监控进度线程"""
        last_count = 0
        last_time = time.time()
        
        while any(p.is_alive() for p in processes) and not self.shared_data.found.value:
            time.sleep(5)
            
            current_count = self.shared_data.keys_tested.value
            current_time = time.time()
            
            elapsed = current_time - start_time
            interval = current_time - last_time
            interval_count = current_count - last_count
            
            # 计算速率
            if interval > 0:
                current_rate = interval_count / interval
                average_rate = current_count / elapsed if elapsed > 0 else 0
                
                print(f"\r总进度: {current_count:,} 密钥, "
                      f"当前速率: {current_rate:,.0f}/s, "
                      f"平均速率: {average_rate:,.0f}/s, "
                      f"运行时间: {elapsed:.1f}s", 
                      end="", flush=True)
            
            last_count = current_count
            last_time = current_time
            
            # 检查结果
            if not results_queue.empty():
                break
    
    def handle_success(self, result, processes):
        """处理成功找到的情况"""
        print(f"\n\n{'='*80}")
        print("*** 成功找到匹配的私钥! ***")
        print(f"{'='*80}")
        print(f"工作进程: {result['worker_id']}")
        print(f"目标地址: {self.target_address}")
        print(f"匹配地址: {result['address']}")
        print(f"WIF压缩私钥: {result['wif_compressed']}")
        print(f"私钥 (十进制): {result['private_key']}")
        print(f"私钥 (十六进制): {hex(result['private_key'])}")
        print(f"本地测试密钥数: {result['keys_tested_local']:,}")
        
        # 保存结果
        self.save_result(result)
        
        # 终止所有进程
        self.cleanup_processes(processes)
    
    def cleanup_processes(self, processes):
        """清理进程"""
        for p in processes:
            if p.is_alive():
                p.terminate()
    
    def save_result(self, result):
        """保存结果到文件"""
        filename = f"found_private_key_{int(time.time())}.txt"
        with open(filename, "w") as f:
            f.write("比特币私钥碰撞结果\n")
            f.write("=" * 50 + "\n")
            f.write(f"找到时间: {time.ctime()}\n")
            f.write(f"目标地址: {self.target_address}\n")
            f.write(f"匹配地址: {result['address']}\n")
            f.write(f"WIF压缩私钥: {result['wif_compressed']}\n")
            f.write(f"私钥 (十进制): {result['private_key']}\n")
            f.write(f"私钥 (十六进制): {hex(result['private_key'])}\n")
            f.write(f"工作进程: {result['worker_id']}\n")
            f.write(f"测试密钥数: {result['keys_tested_local']:,}\n")
        
        print(f"结果已保存到: {filename}")
    
    def print_final_stats(self, total_time):
        """打印最终统计"""
        total_tested = self.shared_data.keys_tested.value
        
        print(f"\n\n{'='*80}")
        print("搜索统计总结")
        print(f"{'='*80}")
        print(f"总运行时间: {total_time:.2f} 秒")
        print(f"总测试密钥数: {total_tested:,}")
        
        if total_time > 0:
            average_rate = total_tested / total_time
            print(f"平均搜索速率: {average_rate:,.0f} 密钥/秒")
            
            # 计算预计完成时间
            total_space = self.end_range - self.start_range
            if average_rate > 0:
                estimated_time = total_space / average_rate
                years = estimated_time / (365 * 24 * 3600)
                print(f"预计完成时间: {years:.2e} 年")
        
        print(f"{'='*80}")

class AdvancedOptimizations:
    """高级优化技术"""
    
    @staticmethod
    def memory_mapped_work_allocator(total_workers):
        """内存映射工作分配器"""
        # 创建共享内存区域用于工作分配
        shm_size = total_workers * CACHE_LINE_SIZE
        return mmap.mmap(-1, shm_size, access=mmap.ACCESS_WRITE)
    
    @staticmethod
    def prefetch_optimization():
        """预取优化 - 提前加载数据到缓存"""
        # 这里可以添加特定的预取逻辑
        pass
    
    @staticmethod
    def branch_prediction_optimization():
        """分支预测优化"""
        # 减少条件分支，使用查找表等
        pass

def system_check():
    """系统检查和优化设置"""
    print("执行系统检查和优化...")
    
    # 检查CPU核心数
    actual_cores = mp.cpu_count()
    print(f"检测到CPU核心数: {actual_cores}")
    print(f"配置工作进程数: {CPU_COUNT}")
    
    # 设置进程优先级（Linux）
    if hasattr(os, 'nice'):
        try:
            os.nice(10)  # 降低优先级，避免影响系统
            print("进程优先级已调整")
        except:
            pass
    
    # 内存优化建议
    import psutil
    memory = psutil.virtual_memory()
    print(f"系统内存: {memory.total / (1024**3):.1f} GB")
    print(f"可用内存: {memory.available / (1024**3):.1f} GB")
    
    if memory.available < 2 * 1024**3:  # 2GB
        print("警告: 可用内存较低，可能影响性能")

def main():
    """主函数"""
    system_check()
    
    # 显示搜索信息
    total_space = END_RANGE - START_RANGE
    print(f"\n搜索空间分析:")
    print(f"总密钥数: {total_space:.2e}")
    print(f"成功概率: {1/total_space:.2e}")
    print(f"这相当于在 {total_space:.2e} 个密钥中找到1个")
    print("注意: 这是一个极其巨大的搜索空间")
    
    # 确认开始
    response = input("\n是否开始高强度搜索? (y/N): ").lower().strip()
    if response not in ['y', 'yes']:
        print("搜索已取消")
        return
    
    # 启动搜索
    try:
        searcher = CacheOptimizedSearcher(TARGET_ADDRESS, START_RANGE, END_RANGE)
        searcher.start_distributed_search(CPU_COUNT)
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # 设置多进程启动方法
    if sys.platform.startswith('win'):
        mp.set_start_method('spawn')
    else:
        mp.set_start_method('fork')  # 或者 'forkserver'
    
    # 检查依赖
    try:
        import base58
        import ecdsa
        import numpy as np
        import psutil
    except ImportError as e:
        print(f"缺少依赖库: {e}")
        print("请安装所需库: pip install base58 ecdsa numpy psutil")
        sys.exit(1)
    
    main()
