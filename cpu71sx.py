import os
import hashlib
import ecdsa
import base58
import multiprocessing as mp
from typing import Tuple
import time

# 目标地址（请确认这是你自己的测试地址！）
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

def private_key_to_wif(private_key_hex: str) -> str:
    """HEX私钥转WIF格式"""
    extended = "80" + private_key_hex
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended)).digest()).hexdigest()[:8]
    return base58.b58encode(bytes.fromhex(extended + checksum)).decode()

def private_key_to_address(private_key_hex: str) -> str:
    """生成比特币地址（压缩公钥）"""
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    
    # 压缩公钥
    pubkey = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
    
    # 地址生成流程
    ripemd160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    payload = b'\x00' + ripemd160
    address = base58.b58encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])
    return address.decode()

def worker(start: int, end: int, mode: str, progress_interval: int = 1000):
    """
    工作进程
    :param start: 起始私钥（整数）
    :param end: 结束私钥（整数）
    :param mode: 'hex' 或 'wif'
    :param progress_interval: 每多少次输出进度
    """
    pid = os.getpid()
    print(f"[进程 {pid}] 开始搜索: {hex(start)} → {hex(end)} ({mode}模式)")
    
    for i in range(start, end):
        private_key_hex = format(i, '064x')  # 补零到64位
        
        try:
            address = private_key_to_address(private_key_hex)
            
            # 输出进度（每progress_interval次）
            if (i - start) % progress_interval == 0:
                if mode == 'hex':
                    print(f"[{pid}] HEX: {private_key_hex} → {address}")
                else:  # wif模式
                    wif = private_key_to_wif(private_key_hex)
                    print(f"[{pid}] WIF: {wif} → {address}")
            
            # 检查是否匹配
            if address == TARGET_ADDRESS:
                if mode == 'hex':
                    result = f"🎉 找到匹配! HEX私钥: {private_key_hex}"
                else:
                    wif = private_key_to_wif(private_key_hex)
                    result = f"🎉 找到匹配! WIF私钥: {wif}"
                
                print(f"\n{result}\n地址: {address}")
                return True
                
        except Exception as e:
            print(f"[{pid}] 错误: {e}")
            continue
    
    print(f"[进程 {pid}] 完成搜索，未找到匹配")
    return False

def main():
    # 依赖检查
    try:
        import ecdsa, base58
    except ImportError:
        print("请安装依赖: pip install ecdsa base58")
        return

    print("="*60)
    print("⚠️  比特币地址碰撞演示 (仅用于学习!)")
    print(f"目标地址: {TARGET_ADDRESS}")
    print("注意：实际成功概率几乎为0，请勿用于非法用途")
    print("="*60)
    
    # 配置参数（示例范围非常小，仅用于演示）
    START_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
    END_HEX   = "0000000000000000000000000000000000000000000000000000000000000010"
    
    start_int = int(START_HEX, 16)
    end_int = int(END_HEX, 16)
    
    # 选择模式
    mode = input("\n选择搜索模式 (输入 hex 或 wif): ").strip().lower()
    if mode not in ['hex', 'wif']:
        print("无效模式，默认使用 hex")
        mode = 'hex'
    
    # 多进程配置
    num_processes = min(mp.cpu_count(), 4)
    total_range = end_int - start_int
    chunk_size = max(1, total_range // num_processes)
    
    print(f"\n配置:")
    print(f"- 搜索范围: {START_HEX} → {END_HEX}")
    print(f"- 总私钥数: {total_range:,}")
    print(f"- 进程数: {num_processes}")
    print(f"- 模式: {mode.upper()}")
    print("-"*40)
    
    # 启动进程
    processes = []
    start_time = time.time()
    
    for i in range(num_processes):
        proc_start = start_int + i * chunk_size
        proc_end = min(start_int + (i+1) * chunk_size, end_int)
        
        if proc_start >= proc_end:
            break
            
        p = mp.Process(
            target=worker, 
            args=(proc_start, proc_end, mode)
        )
        processes.append(p)
        p.start()
    
    # 等待完成
    for p in processes:
        p.join()
    
    elapsed = time.time() - start_time
    print(f"\n🏁 所有进程完成! 耗时: {elapsed:.2f}秒")

if __name__ == "__main__":
    main()
