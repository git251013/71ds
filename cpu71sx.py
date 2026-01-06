import os
import hashlib
import ecdsa
import base58
import multiprocessing as mp
from typing import Tuple, Optional

# 目标地址（注意：这个地址极大概率没有对应的已知私钥）
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdG54CRas7fsVzXU"

def private_key_to_wif(private_key_hex: str) -> str:
    """将私钥转换为 WIF 格式"""
    # 添加前缀 0x80 (主网)
    extended_key = "80" + private_key_hex
    # 计算校验和
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_key)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    # 组合并编码
    wif_key = extended_key + checksum
    return base58.b58encode(bytes.fromhex(wif_key)).decode()

def private_key_to_address(private_key_hex: str) -> str:
    """将私钥转换为比特币地址"""
    # 私钥转字节
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # 使用 secp256k1 曲线生成公钥
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    # 压缩公钥（以 02 或 03 开头）
    public_key = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
    
    # SHA256 -> RIPEMD160
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # 添加版本字节 (0x00 for mainnet)
    versioned_payload = b'\x00' + ripemd160_hash
    
    # 双 SHA256 校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    # Base58 编码
    address_bytes = versioned_payload + checksum
    return base58.b58encode(address_bytes).decode()

def worker(start: int, end: int, result_queue: mp.Queue) -> None:
    """工作进程：在指定范围内搜索"""
    print(f"进程 {os.getpid()} 开始搜索范围: {hex(start)} - {hex(end)}")
    
    for i in range(start, end):
        # 转换为 64 位十六进制（补零到 64 字符）
        private_key_hex = format(i, '064x')
        
        # 生成地址
        address = private_key_to_address(private_key_hex)
        
        if address == TARGET_ADDRESS:
            wif = private_key_to_wif(private_key_hex)
            result_queue.put((private_key_hex, wif, address))
            print(f"🎉 找到了！私钥: {private_key_hex}")
            return
        
        # 每处理一定数量显示进度（可选）
        if i % 100000 == 0:
            print(f"进程 {os.getpid()}: 已处理 {i - start} 个密钥")

def main():
    # 安装依赖提示
    try:
        import ecdsa
        import base58
    except ImportError:
        print("请先安装依赖: pip install ecdsa base58")
        return
    
    print("⚠️  警告：比特币地址碰撞在计算上不可行")
    print(f"目标地址: {TARGET_ADDRESS}")
    print("这只是一个教学演示，实际无法在合理时间内找到结果\n")
    
    # 设置搜索范围（示例：只搜索很小的范围）
    START_RANGE = 0x10000000000000000000000000000000000000000000004eabce0170f4d1dad0
    END_RANGE = 0x10000000000000000000000000000000000000000000004eabce0170f4d1dadf
    
    # 计算范围大小
    total_range = END_RANGE - START_RANGE
    num_processes = min(mp.cpu_count(), 4)  # 限制进程数
    chunk_size = total_range // num_processes
    
    print(f"搜索范围: {hex(START_RANGE)} - {hex(END_RANGE)}")
    print(f"总密钥数: {total_range:,}")
    print(f"使用进程数: {num_processes}\n")
    
    # 创建结果队列
    result_queue = mp.Queue()
    processes = []
    
    # 启动进程
    for i in range(num_processes):
        start = START_RANGE + i * chunk_size
        end = START_RANGE + (i + 1) * chunk_size if i < num_processes - 1 else END_RANGE
        
        p = mp.Process(target=worker, args=(start, end, result_queue))
        processes.append(p)
        p.start()
    
    # 等待结果或所有进程结束
    found = False
    for p in processes:
        p.join()
        if not result_queue.empty():
            private_key, wif, address = result_queue.get()
            print(f"\n✅ 成功找到匹配！")
            print(f"私钥 (HEX): {private_key}")
            print(f"私钥 (WIF): {wif}")
            print(f"地址: {address}")
            found = True
            break
    
    if not found:
        print("\n❌ 在指定范围内未找到匹配的私钥")

if __name__ == "__main__":
    main()
