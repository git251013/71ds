import sys
from bit import Key
import time
import os
import multiprocessing
import logging
from datetime import datetime
import secrets

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bitcoin_search.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class CheckedKeysManager:
    """管理已检查的密钥，避免重复检查"""
    def __init__(self):
        self.lock = multiprocessing.Lock()
        self.checked_keys_file = "checked_keys.txt"
        # 初始化文件
        if not os.path.exists(self.checked_keys_file):
            with open(self.checked_keys_file, 'w') as f:
                f.write("# 已检查的私钥记录\n")
    
    def add_key(self, hex_key):
        """添加已检查的密钥"""
        try:
            with self.lock:
                with open(self.checked_keys_file, 'a') as f:
                    f.write(f"{hex_key}\n")
            return True
        except Exception as e:
            logger.error(f"添加密钥到记录文件失败: {e}")
            return False
    
    def is_checked(self, hex_key):
        """检查密钥是否已被检查过"""
        try:
            with self.lock:
                if not os.path.exists(self.checked_keys_file):
                    return False
                    
                with open(self.checked_keys_file, 'r') as f:
                    for line in f:
                        if line.strip() == hex_key:
                            return True
                return False
        except Exception as e:
            logger.error(f"检查密钥记录失败: {e}")
            return False

# 全局变量，用于跟踪已检查的密钥（跨进程）
checked_keys_manager = None

def init_checked_keys_manager():
    """初始化已检查密钥管理器"""
    global checked_keys_manager
    checked_keys_manager = CheckedKeysManager()

def process_range(args):
    """处理指定范围的私钥搜索"""
    first, last, process_id = args
    
    logger.info(f"进程 {process_id} 开始 | 范围: {hex(first)} - {hex(last)}")
    
    # 目标比特币地址
    WINNING_ADDRESS = '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR'
    
    start_time = time.time()
    keys_checked = 0
    last_log_time = start_time
    
    # 计算范围大小
    range_size = last - first
    
    try:
        # 在指定范围内随机搜索
        while True:
            # 在范围内生成随机数
            random_num = first + secrets.randbelow(range_size + 1)
            hex_string = hex(random_num)[2:].upper().zfill(64)
            
            # 检查这个密钥是否已经被其他进程检查过
            if checked_keys_manager and checked_keys_manager.is_checked(hex_string):
                continue  # 跳过已检查的密钥
            
            # 标记这个密钥为已检查
            if checked_keys_manager:
                checked_keys_manager.add_key(hex_string)
            
            # 检查密钥
            result = check_key(hex_string, WINNING_ADDRESS, process_id, keys_checked)
            keys_checked += 1
            
            if result:
                return result
                
            # 每10000次检查记录一次进度
            if keys_checked % 10000 == 0:
                current_time = time.time()
                if current_time - last_log_time >= 60:  # 每60秒记录一次
                    elapsed = current_time - start_time
                    keys_per_sec = keys_checked / elapsed if elapsed > 0 else 0
                    
                    logger.info(
                        f"进程 {process_id} 进度: {keys_checked:,} 密钥检查完毕 | "
                        f"速度: {keys_per_sec:,.0f} 密钥/秒 | "
                        f"运行时间: {elapsed/3600:.1f} 小时"
                    )
                    last_log_time = current_time
                
    except Exception as e:
        logger.error(f"进程 {process_id} 发生严重错误: {e}")
        return {'status': 'error', 'process_id': process_id, 'error': str(e)}
    
    # 理论上不会到达这里，因为随机搜索是无限的
    elapsed = time.time() - start_time
    keys_per_sec = keys_checked / elapsed if elapsed > 0 else 0
    
    logger.info(
        f"进程 {process_id} 完成 | "
        f"总计检查: {keys_checked:,} 密钥 | "
        f"平均速度: {keys_per_sec:,.0f} 密钥/秒 | "
        f"耗时: {elapsed/3600:.2f} 小时"
    )
    
    return {
        'status': 'completed',
        'process_id': process_id,
        'keys_checked': keys_checked,
        'time_elapsed': elapsed
    }

def check_key(hex_string, target_address, process_id, keys_checked):
    """检查单个密钥是否匹配目标地址"""
    try:
        my_key = Key.from_hex(hex_string)
        
        # 检查是否匹配目标地址
        if my_key and my_key.address == target_address:
            logger.critical(f"🎉 找到匹配的获胜者!!! 进程: {process_id}")
            logger.critical(f"获胜私钥: {my_key}")
            logger.critical(f"匹配地址: {my_key.address}")
            
            # 保存结果到文件
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"WINNER_{timestamp}_process{process_id}.txt"
            
            with open(filename, 'w') as file:
                file.write("比特币私钥搜索 - 找到获胜者!\n")
                file.write(f"时间: {datetime.now()}\n")
                file.write(f"进程ID: {process_id}\n")
                file.write(f"获胜私钥: {my_key}\n")
                file.write(f"私钥(十六进制): {hex_string}\n")
                file.write(f"匹配地址: {my_key.address}\n")
                file.write(f"已检查密钥数: {keys_checked:,}\n")
            
            # 同时写入主获胜文件
            with open("MAIN_WINNER.txt", 'w') as file:
                file.write(f"获胜私钥: {my_key}\n")
                file.write(f"私钥(十六进制): {hex_string}\n")
                file.write(f"地址: {my_key.address}\n")
            
            return {
                'status': 'success',
                'process_id': process_id,
                'private_key': str(my_key),
                'hex_key': hex_string,
                'address': my_key.address,
                'keys_checked': keys_checked
            }
    except Exception as e:
        logger.warning(f"进程 {process_id} 无效密钥 {hex_string}: {e}")
    
    return None

def main():
    """主函数"""
    logger.info("🚀 启动比特币私钥搜索程序")
    
    # 搜索配置
    first = int('970436974004923190478', 10)  # 起始值
    last = int('970436974005023790478', 10)   # 结束值
    
    # 设置进程数量
    num_processes = 120
    
    logger.info(f"搜索范围: {hex(first)} - {hex(last)}")
    logger.info(f"总密钥数: {(last - first + 1):,}")
    logger.info(f"启动进程数: {num_processes}")
    
    # 创建任务列表 - 所有进程使用相同的范围
    tasks = []
    for i in range(num_processes):
        tasks.append((first, last, i + 1))
        logger.info(f"进程 {i+1:3d}: 范围随机模式 - {hex(first)} - {hex(last)}")
    
    logger.info("开始并行搜索...")
    start_time = time.time()
    
    # 初始化已检查密钥管理器
    init_checked_keys_manager()
    
    # 使用进程池并行处理
    with multiprocessing.Pool(processes=num_processes, initializer=init_checked_keys_manager) as pool:
        try:
            results = pool.map(process_range, tasks)
        except KeyboardInterrupt:
            logger.info("收到中断信号，正在停止所有进程...")
            pool.terminate()
            pool.join()
            return
        except Exception as e:
            logger.error(f"进程池发生错误: {e}")
            return
    
    # 分析结果
    total_time = time.time() - start_time
    total_keys = 0
    completed_processes = 0
    
    for result in results:
        if result and 'status' in result:
            if result['status'] == 'success':
                logger.critical("🎊 搜索成功完成！找到获胜私钥！")
                logger.critical(f"私钥: {result.get('private_key', '未知')}")
                logger.critical(f"地址: {result.get('address', '未知')}")
            elif result['status'] == 'completed':
                completed_processes += 1
                total_keys += result.get('keys_checked', 0)
    
    logger.info(f"搜索总结:")
    logger.info(f"总运行时间: {total_time/3600:.2f} 小时")
    logger.info(f"总检查密钥数: {total_keys:,}")
    logger.info(f"完成进程数: {completed_processes}/{num_processes}")
    if total_time > 0:
        logger.info(f"平均速度: {total_keys/total_time:,.0f} 密钥/秒")
    
    # 保存总结报告
    with open("search_summary.txt", 'w') as f:
        f.write(f"比特币私钥搜索总结报告\n")
        f.write(f"生成时间: {datetime.now()}\n")
        f.write(f"搜索范围: {hex(first)} - {hex(last)}\n")
        f.write(f"进程数量: {num_processes}\n")
        f.write(f"总运行时间: {total_time/3600:.2f} 小时\n")
        f.write(f"总检查密钥数: {total_keys:,}\n")
        if total_time > 0:
            f.write(f"平均速度: {total_keys/total_time:,.0f} 密钥/秒\n")
        
        # 检查是否有获胜者
        winners = [r for r in results if r and 'status' in r and r['status'] == 'success']
        if winners:
            f.write(f"\n🎉 找到 {len(winners)} 个获胜者！\n")
            for winner in winners:
                f.write(f"进程 {winner.get('process_id', '未知')}:\n")
                f.write(f"  私钥: {winner.get('private_key', '未知')}\n")
                f.write(f"  地址: {winner.get('address', '未知')}\n")
        else:
            f.write(f"\n未找到匹配的私钥。\n")

if __name__ == "__main__":
    # 设置进程启动方法（在Linux上推荐使用'spawn'）
    multiprocessing.set_start_method('spawn', force=True)
    
    try:
        main()
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序发生错误: {e}")
        raise
