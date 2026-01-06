import os
import hashlib
import ecdsa
import base58
import multiprocessing as mp
from typing import Tuple
import time

# 目标地址（请确认这是你自己的测试地址！）
TARGET_ADDRESS = "1PWo3JeB"

def private_key_to_wif(private_key_hex: str) -> str:
    """HEX私钥转WIF格式（修复压缩标志位）"""
    extended = "80" + private_key_hex + "01"  # 添加压缩标志位
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended)).digest()).hexdigest()[:8]
    return base58.b58encode(bytes.fromhex(extended + checksum)).decode()

def private_key_to_address(private_key_hex: str) -> str:
    """生成比特币地址（正确处理压缩公钥）"""
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    
    # 获取原始公钥数据（64字节：x + y）
    pubkey_raw = vk.to_string()
    
    # 确保公钥长度正确
    if len(pubkey_raw) != 64:
        raise ValueError(f"Invalid public key length: {len(pubkey_raw)} bytes")
    
    # 提取x和y坐标（各32字节）
    x = pubkey_raw[:32]
    y = pubkey_raw[32:]
    
    # 根据y坐标的奇偶性确定压缩公钥前缀
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    compressed_pubkey = prefix + x
    
    # 标准比特币地址生成流程（P2PKH）
    sha256 = hashlib.sha256(compressed_pubkey).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    payload = b'\x00' + ripemd160  # 0x00 表示 mainnet P2PKH
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum)
    return address.decode()

def verify_address_match(private_key_hex: str, expected_address: str) -> bool:
    """验证私钥是否生成指定地址"""
    return private_key_to_address(private_key_hex) == expected_address

def worker(start: int, end: int, mode: str, progress_interval: int = 1000):
    """
    工作进程（添加验证逻辑）
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
            
            # 验证地址匹配
            if address == TARGET_ADDRESS:
                if verify_address_match(private_key_hex, TARGET_ADDRESS):
                    if mode == 'hex':
                        result = f"🎉 找到匹配! HEX私钥: {private_key_hex}"
                    else:
                        wif = private_key_to_wif(private_key_hex)
                        result = f"🎉 找到匹配! WIF私钥: {wif}"
                    
                    print(f"\n{result}\n地址: {address}")
                    return True
                else:
                    print(f"[{pid}] 警告: 地址匹配但验证失败! {private_key_hex} → {address}")
            
            # 输出进度（每progress_interval次）
            if (i - start) % progress_interval == 0:
                if mode == 'hex':
                    print(f"[{pid}] HEX: {private_key_hex} → {address}")
                else:
                    wif = private_key_to_wif(private_key_hex)
                    print(f"[{pid}] WIF: {wif} → {address}")
            
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
    
    # 配置参数
    START_HEX = "00000000000000000000000000000000000000000000004eabce0170f4d1dad0"
    END_HEX   = "00000000000000000000000000000000000000000000004eabce0170f4d1daff"
    
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
    # 添加测试用例以验证地址生成函数
    test_priv = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
    expected_addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    generated_addr = private_key_to_address(test_priv)
    
    print(f"\n{'='*30} 测试验证 {'='*30}")
    print(f"测试私钥: {test_priv}")
    print(f"预期地址: {expected_addr}")
    print(f"生成地址: {generated_addr}")
    
    if generated_addr == expected_addr:
        print("✅ 地址生成函数测试通过!")
    else:
        print("❌ 地址生成函数测试失败!")
        print("请检查 ecdsa 库版本或实现逻辑")
    
    print(f"{'='*60}\n")
    
    # 运行主程序
    main()
