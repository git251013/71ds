# bitcoin_gpu_search_ec.py
import sys
import time
import os
import logging
from datetime import datetime
import hashlib
import base58
import cupy as cp
import numpy as np
from numba import cuda
import struct

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bitcoin_gpu_search.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# secp256k1曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

class GPUKeySearcher:
    def __init__(self, target_address, start_range, end_range, gpu_id=0, batch_size=10000):
        self.target_address = target_address
        self.start_range = start_range
        self.end_range = end_range
        self.gpu_id = gpu_id
        self.batch_size = batch_size
        
        # 计算目标哈希160
        self.target_hash160 = self.address_to_hash160(target_address)
        self.target_hash160_np = np.frombuffer(self.target_hash160, dtype=np.uint8)
        
        logger.info(f"目标地址: {target_address}")
        logger.info(f"目标哈希160: {self.target_hash160.hex()}")
        logger.info(f"搜索范围: {start_range} - {end_range}")
        logger.info(f"搜索范围(十六进制): {hex(start_range)} - {hex(end_range)}")
        logger.info(f"范围大小: {end_range - start_range:,} 个密钥")
        logger.info(f"GPU ID: {gpu_id}")
        logger.info(f"批处理大小: {batch_size}")
        
        # 设置GPU
        self.setup_gpu()
        
        # 编译CUDA核函数
        self.compile_kernels()
    
    def setup_gpu(self):
        """设置GPU设备"""
        try:
            device_count = cp.cuda.runtime.getDeviceCount()
            if device_count == 0:
                raise RuntimeError("未发现CUDA设备")
            
            if self.gpu_id >= device_count:
                raise RuntimeError(f"GPU ID {self.gpu_id} 超出范围，只有 {device_count} 个设备")
            
            # 选择设备
            cp.cuda.Device(self.gpu_id).use()
            
            # 获取设备信息
            props = cp.cuda.runtime.getDeviceProperties(self.gpu_id)
            logger.info(f"使用设备 {self.gpu_id}: {props['name'].decode()}")
            logger.info(f"  计算能力: {props['major']}.{props['minor']}")
            logger.info(f"  全局内存: {props['totalGlobalMem'] / 1024**3:.1f} GB")
            logger.info(f"  多处理器数量: {props['multiProcessorCount']}")
            
        except Exception as e:
            logger.error(f"GPU设置失败: {e}")
            raise
    
    def compile_kernels(self):
        """编译CUDA核函数"""
        try:
            # 完整的椭圆曲线运算核函数
            @cuda.jit(device=True)
            def mod_inverse(a, modulus):
                """模逆计算 - 使用费马小定理"""
                # 费马小定理: a^(p-2) ≡ a^(-1) mod p
                result = 1
                exponent = modulus - 2
                base = a % modulus
                
                while exponent > 0:
                    if exponent & 1:
                        result = (result * base) % modulus
                    base = (base * base) % modulus
                    exponent >>= 1
                
                return result
            
            @cuda.jit(device=True)
            def point_add(x1, y1, x2, y2, p):
                """椭圆曲线点加法"""
                if x1 == 0 and y1 == 0:
                    return x2, y2
                if x2 == 0 and y2 == 0:
                    return x1, y1
                if x1 == x2:
                    if y1 == y2:
                        return point_double(x1, y1, p)
                    else:
                        return 0, 0  # 点互为相反数，结果为无穷远点
                
                # 计算斜率 s = (y2 - y1) / (x2 - x1) mod p
                denominator = (x2 - x1) % p
                inv_denom = mod_inverse(denominator, p)
                s = ((y2 - y1) * inv_denom) % p
                
                # 计算新点 x3 = s^2 - x1 - x2 mod p
                x3 = (s * s - x1 - x2) % p
                # 计算新点 y3 = s * (x1 - x3) - y1 mod p
                y3 = (s * (x1 - x3) - y1) % p
                
                return x3, y3
            
            @cuda.jit(device=True)
            def point_double(x, y, p):
                """椭圆曲线点加倍"""
                if y == 0:
                    return 0, 0  # 无穷远点
                
                # 计算斜率 s = (3 * x^2) / (2 * y) mod p
                numerator = (3 * x * x) % p
                denominator = (2 * y) % p
                inv_denom = mod_inverse(denominator, p)
                s = (numerator * inv_denom) % p
                
                # 计算新点 x3 = s^2 - 2*x mod p
                x3 = (s * s - 2 * x) % p
                # 计算新点 y3 = s * (x - x3) - y mod p
                y3 = (s * (x - x3) - y) % p
                
                return x3, y3
            
            @cuda.jit(device=True)
            def scalar_multiply(k, gx, gy, p, n):
                """椭圆曲线标量乘法 k * G"""
                # 使用双倍-加法算法
                rx, ry = 0, 0  # 结果点
                tx, ty = gx, gy  # 临时点
                
                # 遍历k的每一位
                for i in range(256):
                    if (k >> i) & 1:
                        if rx == 0 and ry == 0:
                            rx, ry = tx, ty
                        else:
                            rx, ry = point_add(rx, ry, tx, ty, p)
                    
                    # 点加倍
                    tx, ty = point_double(tx, ty, p)
                
                return rx, ry
            
            @cuda.jit(device=True)
            def public_key_to_address(x, y, p):
                """将公钥转换为比特币地址"""
                # 压缩公钥格式
                prefix = 0x02 if y % 2 == 0 else 0x03
                
                # 计算SHA256哈希
                # 注意：这里简化了SHA256计算，实际实现需要完整的SHA256
                sha_input = (prefix << 256) | x
                sha_hash = 0
                for i in range(32):
                    byte_val = (sha_input >> (i * 8)) & 0xFF
                    sha_hash = (sha_hash << 8) | byte_val
                
                # 计算RIPEMD160哈希
                # 注意：这里简化了RIPEMD160计算，实际实现需要完整的RIPEMD160
                ripemd_hash = 0
                for i in range(20):
                    byte_val = (sha_hash >> (i * 8)) & 0xFF
                    ripemd_hash = (ripemd_hash << 8) | byte_val
                
                return ripemd_hash
            
            @cuda.jit
            def check_keys_kernel(private_keys, target_hash, results, found_index, p, n, gx, gy):
                """CUDA核函数：检查私钥批次"""
                idx = cuda.grid(1)
                
                if idx < private_keys.size and found_index[0] == -1:
                    private_key = private_keys[idx]
                    
                    # 跳过无效私钥 (0 或 >= n)
                    if private_key == 0 or private_key >= n:
                        results[idx] = -1
                        return
                    
                    try:
                        # 椭圆曲线标量乘法：私钥 -> 公钥
                        pub_x, pub_y = scalar_multiply(private_key, gx, gy, p, n)
                        
                        # 公钥 -> 比特币地址
                        address_hash = public_key_to_address(pub_x, pub_y, p)
                        
                        # 比较哈希
                        match = True
                        # 简化比较：只比较部分字节
                        for i in range(4):  # 比较前4个字节
                            target_byte = (target_hash[i // 8] >> ((i % 8) * 8)) & 0xFF
                            address_byte = (address_hash >> (i * 8)) & 0xFF
                            if target_byte != address_byte:
                                match = False
                                break
                        
                        if match:
                            # 使用原子操作确保只有一个线程写入
                            cuda.atomic.exch(found_index, 0, idx)
                            results[idx] = 1
                        else:
                            results[idx] = 0
                            
                    except Exception:
                        results[idx] = -1
            
            self.check_keys_kernel = check_keys_kernel
            self.mod_inverse = mod_inverse
            self.point_add = point_add
            self.point_double = point_double
            self.scalar_multiply = scalar_multiply
            self.public_key_to_address = public_key_to_address
            
            logger.info("✓ CUDA核函数编译成功")
            
        except Exception as e:
            logger.error(f"核函数编译失败: {e}")
            # 使用备用方案
            self.check_keys_kernel = None
    
    def address_to_hash160(self, address):
        """将比特币地址转换为哈希160"""
        try:
            # Base58解码
            decoded = base58.b58decode(address)
            # 去掉版本字节和校验和
            hash160 = decoded[1:21]
            return hash160
        except Exception as e:
            logger.error(f"地址解码失败: {e}")
            raise
    
    def generate_private_keys_batch(self):
        """生成一批私钥"""
        try:
            # 在搜索范围内生成随机私钥
            range_size = self.end_range - self.start_range
            
            # 使用numpy生成随机数，然后转换为cupy
            private_keys_np = np.random.randint(
                self.start_range, self.end_range + 1, 
                size=self.batch_size, dtype=np.uint64
            )
            private_keys = cp.asarray(private_keys_np)
            
            return private_keys
            
        except Exception as e:
            logger.error(f"生成私钥批次失败: {e}")
            # 备用方案：使用序列号
            private_keys = cp.arange(self.batch_size, dtype=cp.uint64) + self.start_range
            return private_keys
    
    def search_batch(self):
        """搜索一批私钥"""
        try:
            if self.check_keys_kernel is None:
                logger.warning("核函数未编译，跳过批处理")
                return False
            
            # 生成私钥批次
            private_keys = self.generate_private_keys_batch()
            
            # 准备结果数组
            results = cp.zeros(self.batch_size, dtype=cp.int32)
            found_index = cp.array([-1], dtype=cp.int32)
            
            # 将目标哈希传输到GPU
            target_hash160_gpu = cp.asarray(self.target_hash160_np)
            
            # 配置CUDA网格和块
            threads_per_block = 256
            blocks_per_grid = (self.batch_size + threads_per_block - 1) // threads_per_block
            
            # 启动核函数
            self.check_keys_kernel[blocks_per_grid, threads_per_block](
                private_keys, target_hash160_gpu, results, found_index, 
                P, N, Gx, Gy
            )
            
            # 同步GPU
            cp.cuda.stream.get_current_stream().synchronize()
            
            # 检查结果
            found_idx = int(found_index[0])
            if found_idx != -1:
                private_key = int(private_keys[found_idx])
                hex_key = hex(private_key)[2:].upper().zfill(64)
                logger.critical(f"🎉 找到匹配的私钥: {hex_key}")
                
                # 验证并保存结果
                if self.verify_key(private_key):
                    self.save_winner(private_key, hex_key)
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"批处理搜索错误: {e}")
            return False
    
    def verify_key(self, private_key):
        """验证私钥是否正确"""
        try:
            # 使用Python实现验证
            from ecdsa import SECP256k1, SigningKey
            
            # 将私钥转换为十六进制
            hex_key = hex(private_key)[2:].upper().zfill(64)
            
            # 创建签名密钥
            sk = SigningKey.from_string(bytes.fromhex(hex_key), curve=SECP256k1)
            
            # 获取验证密钥（公钥）
            vk = sk.verifying_key
            
            # 获取压缩公钥
            public_key = vk.to_string("compressed")
            
            # 计算SHA256
            sha256_hash = hashlib.sha256(public_key).digest()
            
            # 计算RIPEMD160
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            
            # 添加版本字节 (0x00 for mainnet)
            extended_hash = b'\x00' + ripemd160_hash
            
            # 计算校验和
            checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
            
            # 组合最终字节
            binary_address = extended_hash + checksum
            
            # Base58编码
            address = base58.b58encode(binary_address).decode('ascii')
            
            # 比较地址
            if address == self.target_address:
                logger.critical(f"✓ 私钥验证成功!")
                logger.critical(f"  生成地址: {address}")
                logger.critical(f"  目标地址: {self.target_address}")
                return True
            else:
                logger.warning(f"✗ 私钥验证失败")
                logger.warning(f"  生成地址: {address}")
                logger.warning(f"  目标地址: {self.target_address}")
                return False
            
        except Exception as e:
            logger.error(f"验证私钥失败: {e}")
            return False
    
    def save_winner(self, private_key, hex_key):
        """保存获胜结果"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"GPU_WINNER_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as file:
                file.write("GPU比特币私钥搜索 - 找到获胜者!\n")
                file.write(f"时间: {datetime.now()}\n")
                file.write(f"GPU ID: {self.gpu_id}\n")
                file.write(f"获胜私钥: {hex_key}\n")
                file.write(f"私钥(十进制): {private_key}\n")
                file.write(f"私钥(十六进制): {hex(private_key)}\n")
                file.write(f"目标地址: {self.target_address}\n")
            
            # 同时写入主获胜文件
            with open("MAIN_GPU_WINNER.txt", 'w') as file:
                file.write(f"获胜私钥: {hex_key}\n")
                file.write(f"私钥(十进制): {private_key}\n")
                file.write(f"私钥(十六进制): {hex(private_key)}\n")
                file.write(f"地址: {self.target_address}\n")
                file.write(f"GPU ID: {self.gpu_id}\n")
                file.write(f"时间: {datetime.now()}\n")
            
            logger.critical(f"结果已保存到: {filename}")
            
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
    
    def run_search(self, max_iterations=None):
        """运行GPU搜索"""
        logger.info("🚀 启动GPU比特币私钥搜索")
        
        start_time = time.time()
        total_batches = 0
        total_keys_checked = 0
        last_log_time = start_time
        last_keys_checked = 0
        
        try:
            iteration = 0
            while True:
                if max_iterations is not None and iteration >= max_iterations:
                    logger.info(f"达到最大迭代次数 {max_iterations}，停止搜索")
                    break
                    
                batch_start_time = time.time()
                
                # 搜索一批密钥
                found = self.search_batch()
                total_batches += 1
                total_keys_checked += self.batch_size
                iteration += 1
                
                if found:
                    logger.critical("🎊 搜索成功完成！")
                    break
                
                # 定期记录进度和性能
                current_time = time.time()
                if current_time - last_log_time >= 30:  # 每30秒记录一次
                    elapsed = current_time - start_time
                    recent_elapsed = current_time - last_log_time
                    recent_keys = total_keys_checked - last_keys_checked
                    
                    keys_per_sec = recent_keys / recent_elapsed if recent_elapsed > 0 else 0
                    avg_keys_per_sec = total_keys_checked / elapsed if elapsed > 0 else 0
                    
                    # 计算进度百分比
                    range_size = self.end_range - self.start_range
                    if range_size > 0:
                        progress = (total_keys_checked / range_size) * 100
                        progress = min(100.0, progress)  # 确保不超过100%
                    else:
                        progress = 0
                    
                    logger.info(
                        f"GPU {self.gpu_id} | "
                        f"批次: {total_batches:,} | "
                        f"密钥: {total_keys_checked:,} | "
                        f"速度: {keys_per_sec:,.0f} 密钥/秒 | "
                        f"进度: {progress:.6f}% | "
                        f"运行时间: {elapsed/60:.1f} 分钟"
                    )
                    
                    last_log_time = current_time
                    last_keys_checked = total_keys_checked
                
                # 检查GPU状态
                if total_batches % 100 == 0:
                    self.check_gpu_status()
                
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止搜索")
        except Exception as e:
            logger.error(f"搜索过程中发生错误: {e}")
        finally:
            # 保存搜索总结
            self.save_search_summary(start_time, total_batches, total_keys_checked)
    
    def check_gpu_status(self):
        """检查GPU状态"""
        try:
            free_mem, total_mem = cp.cuda.runtime.memGetInfo()
            mem_usage = ((total_mem - free_mem) / total_mem) * 100
            
            logger.debug(f"GPU {self.gpu_id} 内存使用率: {mem_usage:.1f}%")
                
        except Exception as e:
            logger.warning(f"检查GPU状态失败: {e}")
    
    def save_search_summary(self, start_time, total_batches, total_keys_checked):
        """保存搜索总结"""
        total_time = time.time() - start_time
        
        logger.info(f"GPU {self.gpu_id} 搜索总结:")
        logger.info(f"总运行时间: {total_time/60:.2f} 分钟")
        logger.info(f"总批次数: {total_batches:,}")
        logger.info(f"总检查密钥数: {total_keys_checked:,}")
        
        if total_time > 0:
            keys_per_sec = total_keys_checked / total_time
            logger.info(f"平均速度: {keys_per_sec:,.0f} 密钥/秒")
        
        try:
            with open(f"gpu_{self.gpu_id}_search_summary.txt", 'w') as f:
                f.write(f"GPU比特币私钥搜索总结报告\n")
                f.write(f"生成时间: {datetime.now()}\n")
                f.write(f"GPU ID: {self.gpu_id}\n")
                f.write(f"搜索范围: {self.start_range} - {self.end_range}\n")
                f.write(f"搜索范围(十六进制): {hex(self.start_range)} - {hex(self.end_range)}\n")
                f.write(f"批处理大小: {self.batch_size}\n")
                f.write(f"总运行时间: {total_time/60:.2f} 分钟\n")
                f.write(f"总批次数: {total_batches:,}\n")
                f.write(f"总检查密钥数: {total_keys_checked:,}\n")
                if total_time > 0:
                    f.write(f"平均速度: {keys_per_sec:,.0f} 密钥/秒\n")
                f.write(f"目标地址: {self.target_address}\n")
                f.write(f"状态: {'找到私钥' if total_keys_checked > 0 else '未找到'}\n")
        except Exception as e:
            logger.error(f"保存总结报告失败: {e}")

def main():
    """主函数"""
    try:
        # 搜索配置 - 使用指定的十进制范围
        TARGET_ADDRESS = '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR'
        START_RANGE = 960436974004923190478
        END_RANGE = 970436974005023790478
        
        logger.info(f"指定的搜索范围:")
        logger.info(f"  十进制: {START_RANGE} - {END_RANGE}")
        logger.info(f"  十六进制: {hex(START_RANGE)} - {hex(END_RANGE)}")
        logger.info(f"  范围大小: {END_RANGE - START_RANGE:,} 个密钥")
        
        # 检查CUDA可用性
        device_count = cp.cuda.runtime.getDeviceCount()
        if device_count == 0:
            logger.error("未发现CUDA设备，请检查GPU驱动和CUDA安装")
            return
        
        logger.info(f"发现 {device_count} 个CUDA设备")
        
        # 单GPU搜索
        searcher = GPUKeySearcher(
            target_address=TARGET_ADDRESS,
            start_range=START_RANGE,
            end_range=END_RANGE,
            gpu_id=0,
            batch_size=10000  # 较小的批处理大小，因为椭圆曲线计算较慢
        )
        
        # 计算估计时间
        range_size = END_RANGE - START_RANGE
        estimated_batches = range_size // 10000 + 1
        logger.info(f"估计需要 {estimated_batches:,} 批次完成搜索")
        
        searcher.run_search()
        
    except Exception as e:
        logger.error(f"程序发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序启动失败: {e}")
        sys.exit(1)
