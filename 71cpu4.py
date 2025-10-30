#!/usr/bin/env python3
"""
比特币私钥碰撞工具 - 120核心优化版本（修复版）
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
搜索范围: 2^70 到 2^71 (压缩格式私钥)
修复了整数范围溢出问题
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
import threading
from threading import Thread
import ctypes
from ctypes import c_uint64, c_ubyte, c_bool
import struct
from concurrent.futures import ProcessPoolExecutor, as_completed

# 常量定义
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
START_RANGE = 1500520536206896083277
END_RANGE = 1500520536206996083277
CPU_COUNT = min(120, mp.cpu_count())  # 限制最大进程数
BATCH_SIZE = 10000  # 调整批量大小

class FixedKeyGenerator:
    """修复的密钥生成器 - 避免整数溢出"""
    
    def __init__(self):
        self.curve = SECP256k1
        self.version_byte = b'\x00'
        self.compression_flag = b'\x01'
        self.wif_version = b'\x80'
        
    def generate_secure_batch(self, count, start_range, end_range):
        """安全生成批量私钥，避免整数溢出"""
        keys = []
        range_size = end_range - start_range
        
        for _ in range(count):
            # 使用安全随机数生成，避免numpy的uint64限制
            key_int = secrets.randbelow(range_size) + start_range
            keys.append(key_int)
        
        return keys
    
    def private_to_compressed_address_batch(self, private_keys):
        """批量处理私钥到地址的转换"""
        addresses = []
        wif_keys = []
        
        for priv_int in private_keys:
            try:
                # 转换为32字节
                private_key_bytes = priv_int.to_bytes(32, 'big')
                
                # 生成公钥
                sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=SECP256k1)
                vk = sk.get_verifying_key()
                public_key_bytes = vk.to_string("compressed")
                
                # 生成地址
                sha256_hash = hashlib.sha256(public_key_bytes).digest()
                ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
                versioned_payload = self.version_byte + ripemd160_hash
                checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
                binary_address = versioned_payload + checksum
                bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
                
                addresses.append(bitcoin_address)
                
                # 生成WIF
                extended_key = self.wif_version + private_key_bytes + self.compression_flag
                first_sha = hashlib.sha256(extended_key).digest()
                wif_checksum = hashlib.sha256(first_sha).digest()[:4]
                wif = base58.b58encode(extended_key + wif_checksum).decode('utf-8')
                wif_keys.append(wif)
                
            except Exception as e:
                addresses.append(None)
                wif_keys.append(None)
        
        return addresses, wif_keys

class SafeWorker:
    """安全的工作进程 - 避免各种边界条件"""
    
    def __init__(self, worker_id, shared_data, start_range, end_range):
        self.worker_id = worker_id
        self.shared_data = shared_data
        self.start_range = start_range
        self.end_range = end_range
        self.range_size = end_range - start_range
        self.key_gen = FixedKeyGenerator()
        
        # 本地统计
        self.local_keys_tested = 0
        self.local_start_time = time.time()
        self.last_report_time = time.time()
        
    def safe_work_loop(self, results_queue):
        """安全的工作循环"""
        print(f"安全工作进程 {self.worker_id} 启动 - 范围: {self.start_range} 到 {self.end_range}")
        
        batch_count = 0
        
        while not self.shared_data.found.value:
            try:
                batch_start = time.time()
                
                # 生成一批密钥
                private_keys = self.key_gen.generate_secure_batch(
                    BATCH_SIZE, self.start_range, self.end_range
                )
                
                # 批量处理地址生成
                addresses, wif_keys = self.key_gen.private_to_compressed_address_batch(private_keys)
                
                # 检查匹配
                for i, address in enumerate(addresses):
                    if self.shared_data.found.value:
                        return
                        
                    if address and address == TARGET_ADDRESS:
                        print(f"\n*** 安全进程 {self.worker_id} 找到匹配! ***")
                        
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
                batch_size = len(private_keys)
                self.local_keys_tested += batch_size
                batch_count += 1
                
                # 定期报告
                current_time = time.time()
                if current_time - self.last_report_time >= 10:  # 每10秒报告一次
                    batch_time = current_time - batch_start
                    total_elapsed = current_time - self.local_start_time
                    
                    batch_rate = batch_size / batch_time if batch_time > 0 else 0
                    total_rate = self.local_keys_tested / total_elapsed if total_elapsed > 0 else 0
                    
                    print(f"安全进程 {self.worker_id}: "
                          f"批次 {batch_count}, 测试: {self.local_keys_tested:,}, "
                          f"速率: {total_rate:,.0f}/s")
                    
                    self.last_report_time = current_time
                
                # 更新全局计数器（更频繁但小批量）
                with self.shared_data.lock:
                    self.shared_data.keys_tested.value += batch_size
                    
            except Exception as e:
                print(f"安全进程 {self.worker_id} 遇到错误: {e}")
                # 继续运行，不要崩溃
                continue
        
        print(f"安全进程 {self.worker_id} 完成")

class RobustSearcher:
    """稳健的搜索器 - 处理各种边界条件"""
    
    def __init__(self, target_address, start_range, end_range):
        self.target_address = target_address
        self.start_range = start_range
        self.end_range = end_range
        self.shared_data = self.create_shared_data()
        
    def create_shared_data(self):
        """创建共享数据"""
        class SharedData:
            def __init__(self):
                self.found = Value(c_bool, False)
                self.keys_tested = Value(c_uint64, 0)
                self.lock = Lock()
        
        return SharedData()
    
    def calculate_work_ranges(self, num_workers):
        """计算工作范围，避免整数溢出"""
        ranges = []
        total_range = self.end_range - self.start_range
        
        if total_range <= 0:
            raise ValueError("无效的范围")
        
        # 确保每个工作进程的范围是合理的
        chunk_size = total_range // num_workers
        remainder = total_range % num_workers
        
        current = self.start_range
        for i in range(num_workers):
            # 当前块的大小
            size = chunk_size + (1 if i < remainder else 0)
            
            # 确保不会超出范围
            end = current + size
            if end > self.end_range:
                end = self.end_range
            
            ranges.append((current, end))
            current = end
            
            # 如果已经到达终点，提前结束
            if current >= self.end_range:
                break
        
        return ranges
    
    def start_robust_search(self, num_workers=None):
        """启动稳健的搜索"""
        if num_workers is None:
            num_workers = CPU_COUNT
        
        # 限制最大工作进程数
        num_workers = min(num_workers, CPU_COUNT)
        
        print("=" * 80)
        print("比特币私钥碰撞工具 - 稳健版本")
        print("=" * 80)
        print(f"目标地址: {self.target_address}")
        print(f"搜索范围: {self.start_range} 到 {self.end_range}")
        print(f"工作进程数: {num_workers}")
        print(f"批量大小: {BATCH_SIZE}")
        print(f"总搜索空间: {self.end_range - self.start_range:,} 个密钥")
        print("=" * 80)
        
        # 计算工作范围
        work_ranges = self.calculate_work_ranges(num_workers)
        actual_workers = len(work_ranges)
        
        if actual_workers < num_workers:
            print(f"调整工作进程数: {num_workers} -> {actual_workers}")
        
        start_time = time.time()
        
        with Manager() as manager:
            results_queue = manager.Queue()
            processes = []
            
            # 启动工作进程
            for i, (start, end) in enumerate(work_ranges):
                worker = SafeWorker(i, self.shared_data, start, end)
                p = Process(target=worker.safe_work_loop, args=(results_queue,))
                processes.append(p)
                p.start()
                print(f"启动安全进程 {i}: 范围 {start} - {end}")
            
            # 启动监控线程
            monitor_thread = Thread(
                target=self.safe_monitor_progress, 
                args=(start_time, processes, results_queue),
                daemon=True
            )
            monitor_thread.start()
            
            try:
                # 主循环
                while any(p.is_alive() for p in processes):
                    time.sleep(2)
                    
                    # 检查结果
                    if not results_queue.empty():
                        result = results_queue.get()
                        self.handle_success(result, processes)
                        break
                    
                    # 检查是否有进程崩溃
                    for p in processes:
                        if not p.is_alive() and p.exitcode != 0:
                            print(f"警告: 进程 {processes.index(p)} 异常退出, 代码: {p.exitcode}")
                
            except KeyboardInterrupt:
                print("\n用户中断搜索...")
                self.safe_cleanup(processes)
            
            except Exception as e:
                print(f"主循环错误: {e}")
                self.safe_cleanup(processes)
            
            finally:
                # 等待所有进程结束
                for p in processes:
                    p.join(timeout=5)
                    if p.is_alive():
                        p.terminate()
                
                total_time = time.time() - start_time
                self.print_final_stats(total_time)
    
    def safe_monitor_progress(self, start_time, processes, results_queue):
        """安全的进度监控"""
        last_count = 0
        last_time = time.time()
        
        while any(p.is_alive() for p in processes) and not self.shared_data.found.value:
            try:
                time.sleep(8)  # 更长的间隔减少负载
                
                current_count = self.shared_data.keys_tested.value
                current_time = time.time()
                
                elapsed = current_time - start_time
                interval = current_time - last_time
                interval_count = current_count - last_count
                
                if interval > 0:
                    current_rate = interval_count / interval
                    average_rate = current_count / elapsed if elapsed > 0 else 0
                    
                    # 格式化输出
                    print(f"\r总进度: {current_count:,} 密钥, "
                          f"速率: {current_rate:,.0f}/s, "
                          f"平均: {average_rate:,.0f}/s, "
                          f"时间: {elapsed:.1f}s", 
                          end="", flush=True)
                
                last_count = current_count
                last_time = current_time
                
                # 检查活跃进程数
                alive_count = sum(1 for p in processes if p.is_alive())
                if alive_count < len(processes):
                    print(f"\n警告: 只有 {alive_count}/{len(processes)} 个进程存活")
                
            except Exception as e:
                print(f"\n监控错误: {e}")
                continue
    
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
        
        # 安全终止所有进程
        self.safe_cleanup(processes)
    
    def safe_cleanup(self, processes):
        """安全清理进程"""
        print("正在终止工作进程...")
        for p in processes:
            if p.is_alive():
                try:
                    p.terminate()
                except:
                    pass
        
        # 等待终止
        for p in processes:
            try:
                p.join(timeout=2)
            except:
                pass
    
    def save_result(self, result):
        """保存结果到文件"""
        timestamp = int(time.time())
        filename = f"found_private_key_{timestamp}.txt"
        
        try:
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
        except Exception as e:
            print(f"保存结果失败: {e}")
    
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

def system_check():
    """系统检查"""
    print("执行系统检查...")
    
    # 检查CPU核心数
    actual_cores = mp.cpu_count()
    print(f"检测到CPU核心数: {actual_cores}")
    print(f"配置工作进程数: {CPU_COUNT}")
    
    # 检查Python版本
    print(f"Python版本: {sys.version}")
    
    # 检查依赖
    try:
        import base58
        import ecdsa
        print("依赖检查: 通过")
    except ImportError as e:
        print(f"依赖检查失败: {e}")
        return False
    
    return True

def main():
    """主函数"""
    if not system_check():
        print("系统检查失败，请安装所需依赖")
        print("pip install base58 ecdsa")
        return
    
    # 显示搜索信息
    total_space = END_RANGE - START_RANGE
    print(f"\n搜索空间分析:")
    print(f"总密钥数: {total_space:.2e}")
    print(f"成功概率: {1/total_space:.2e}")
    print(f"这相当于在 {total_space:.2e} 个密钥中找到1个")
    print("注意: 这是一个极其巨大的搜索空间")
    
    # 确认开始
    response = input("\n是否开始搜索? (y/N): ").lower().strip()
    if response not in ['y', 'yes']:
        print("搜索已取消")
        return
    
    # 启动搜索
    try:
        searcher = RobustSearcher(TARGET_ADDRESS, START_RANGE, END_RANGE)
        searcher.start_robust_search(CPU_COUNT)
    except Exception as e:
        print(f"启动错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # 设置多进程启动方法
    if sys.platform.startswith('win'):
        mp.set_start_method('spawn')
    else:
        mp.set_start_method('fork')
    
    main()
