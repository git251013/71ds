import sys
from bit import Key
import time
import os
import multiprocessing
import logging
from datetime import datetime

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

def process_range(args):
    """处理指定范围的私钥搜索"""
    first, last, process_id = args
    logger.info(f"进程 {process_id} 开始处理范围: {hex(first)} - {hex(last)}")
    
    # 目标比特币地址
    WINNING_ADDRESS = '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR'
    
    start_time = time.time()
    keys_checked = 0
    last_log_time = start_time
    
    try:
        for num in range(first, last + 1):
            hex_string = hex(num)[2:].upper().zfill(64)
            
            try:
                my_key = Key.from_hex(hex_string)
                keys_checked += 1
                
                # 定期记录进度
                current_time = time.time()
                if current_time - last_log_time >= 60:  # 每60秒记录一次
                    elapsed = current_time - start_time
                    keys_per_sec = keys_checked / elapsed if elapsed > 0 else 0
                    remaining_keys = (last - num)
                    eta_seconds = remaining_keys / keys_per_sec if keys_per_sec > 0 else 0
                    
                    logger.info(
                        f"进程 {process_id} 进度: {keys_checked:,} 密钥检查完毕 | "
                        f"速度: {keys_per_sec:,.0f} 密钥/秒 | "
                        f"ETA: {eta_seconds/3600:.1f} 小时"
                    )
                    last_log_time = current_time
                
                # 检查是否匹配目标地址
                if my_key.address == WINNING_ADDRESS:
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
                        file.write(f"搜索范围: {hex(first)} - {hex(last)}\n")
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
                logger.error(f"进程 {process_id} 处理密钥时出错: {e}")
                continue
                
    except Exception as e:
        logger.error(f"进程 {process_id} 发生严重错误: {e}")
        return {'status': 'error', 'process_id': process_id, 'error': str(e)}
    
    # 完成范围搜索
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

def main():
    """主函数"""
    logger.info("🚀 启动比特币私钥搜索程序")
    
    # 设置搜索范围（十六进制）
    first = int('20000000000000000', 16)  # 起始值
    last = int('3ffffffffffffffff', 16)   # 结束值
    
    # 设置进程数量
    num_processes = 120
    
    logger.info(f"搜索范围: {hex(first)} - {hex(last)}")
    logger.info(f"总密钥数: {(last - first + 1):,}")
    logger.info(f"启动进程数: {num_processes}")
    
    # 计算每个进程的范围
    range_size = last - first + 1
    part_size = range_size // num_processes
    
    # 创建任务列表
    tasks = []
    for i in range(num_processes):
        part_first = first + (i * part_size)
        part_last = part_first + part_size - 1
        
        # 调整最后一个进程的范围以包含剩余值
        if i == num_processes - 1:
            part_last = last
            
        tasks.append((part_first, part_last, i + 1))
        
        logger.info(f"进程 {i+1:3d}: {hex(part_first)} - {hex(part_last)} "
                   f"(约 {(part_last - part_first + 1):,} 个密钥)")
    
    logger.info("开始并行搜索...")
    start_time = time.time()
    
    # 使用进程池并行处理
    with multiprocessing.Pool(processes=num_processes) as pool:
        results = pool.map(process_range, tasks)
    
    # 分析结果
    total_time = time.time() - start_time
    total_keys = 0
    completed_processes = 0
    
    for result in results:
        if result['status'] == 'success':
            logger.critical("🎊 搜索成功完成！找到获胜私钥！")
            logger.critical(f"私钥: {result['private_key']}")
            logger.critical(f"地址: {result['address']}")
        elif result['status'] == 'completed':
            completed_processes += 1
            total_keys += result['keys_checked']
    
    logger.info(f"搜索总结:")
    logger.info(f"总运行时间: {total_time/3600:.2f} 小时")
    logger.info(f"总检查密钥数: {total_keys:,}")
    logger.info(f"完成进程数: {completed_processes}/{num_processes}")
    logger.info(f"平均速度: {total_keys/total_time:,.0f} 密钥/秒")
    
    # 保存总结报告
    with open("search_summary.txt", 'w') as f:
        f.write(f"比特币私钥搜索总结报告\n")
        f.write(f"生成时间: {datetime.now()}\n")
        f.write(f"搜索范围: {hex(first)} - {hex(last)}\n")
        f.write(f"进程数量: {num_processes}\n")
        f.write(f"总运行时间: {total_time/3600:.2f} 小时\n")
        f.write(f"总检查密钥数: {total_keys:,}\n")
        f.write(f"平均速度: {total_keys/total_time:,.0f} 密钥/秒\n")
        
        # 检查是否有获胜者
        winners = [r for r in results if r['status'] == 'success']
        if winners:
            f.write(f"\n🎉 找到 {len(winners)} 个获胜者！\n")
            for winner in winners:
                f.write(f"进程 {winner['process_id']}:\n")
                f.write(f"  私钥: {winner['private_key']}\n")
                f.write(f"  地址: {winner['address']}\n")
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
