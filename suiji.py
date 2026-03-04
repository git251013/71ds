import random
import re
from collections import Counter

def generate_random_hex_list(start=32, end=64, times=32):
    """生成指定次数的随机十六进制数列表"""
    low = start + 1
    high = end - 1
    hex_list = []
    
    print(f"在 ({start}, {end}) 范围内生成 {times} 个随机整数（实际整数范围: {low} ~ {high}）：")
    for i in range(1, times + 1):
        num = random.randint(low, high)
        hex_str = hex(num)  # 如 0x21
        hex_list.append(hex_str)
        print(f"第 {i:2d} 次: {hex_str}")
    
    return hex_list, low, high

def normalize_hex_input(user_input):
    """标准化用户输入的十六进制字符串"""
    s = user_input.strip()
    if s.lower().startswith('0x'):
        clean = s[2:]
    else:
        clean = s
    if not re.fullmatch(r'[0-9a-fA-F]+', clean):
        return None
    try:
        return hex(int(clean, 16))
    except ValueError:
        return None

def search_in_results(hex_list):
    """交互式查找功能"""
    print("\n🔍 查找功能：输入十六进制数（如 3f 或 0x3f），或输入 'quit' 退出。")
    while True:
        query = input(">>> 输入要查找的十六进制数: ").strip()
        if query.lower() in ('quit', 'exit', 'q'):
            print("查找结束。")
            break
        
        normalized = normalize_hex_input(query)
        if normalized is None:
            print("❌ 无效的十六进制格式，请输入如 '3f' 或 '0x3f'")
            continue
        
        val = int(normalized, 16)
        if not (33 <= val <= 63):
            print(f"⚠️  注意：{normalized} 不在有效范围 (0x21 ~ 0x3f)，不会出现在结果中。")
        
        positions = [i+1 for i, h in enumerate(hex_list) if h == normalized]
        if positions:
            print(f"✅ 找到！'{normalized}' 出现在第 {', '.join(map(str, positions))} 次。")
        else:
            print(f"❌ 未找到 '{normalized}'。")

def analyze_results(hex_list, low, high):
    """分析结果：未出现的数、频率统计等"""
    counter = Counter(hex_list)
    
    # 所有可能的十六进制值（33 ~ 63）
    all_possible = {hex(i) for i in range(low, high + 1)}
    generated_set = set(hex_list)
    missing = sorted(all_possible - generated_set, key=lambda x: int(x, 16))
    
    # 频率分析
    if counter:
        min_count = min(counter.values())
        max_count = max(counter.values())
        min_items = sorted([k for k, v in counter.items() if v == min_count], key=lambda x: int(x, 16))
        max_items = sorted([k for k, v in counter.items() if v == max_count], key=lambda x: int(x, 16))
    else:
        min_count = max_count = 0
        min_items = max_items = []

    # 输出分析结果
    print("\n" + "="*50)
    print("📊 分析报告")
    print("="*50)
    print(f"总生成次数: {len(hex_list)}")
    print(f"唯一数值个数: {len(counter)} / {len(all_possible)}")
    
    # 未出现的数
    if missing:
        print(f"\n🚫 未出现的数（共 {len(missing)} 个）:")
        print(", ".join(missing))
    else:
        print("\n✅ 所有数都至少出现了一次！")
    
    # 频率统计
    print(f"\n📉 出现次数最少（{min_count} 次）的数:")
    if min_items:
        print(", ".join(min_items))
    else:
        print("无")
    
    print(f"\n📈 出现次数最多（{max_count} 次）的数:")
    if max_items:
        print(", ".join(max_items))
    else:
        print("无")
    
    # 主程序
if __name__ == "__main__":
    # 生成随机序列
    results, low, high = generate_random_hex_list(start=1099511627776, end=2199023255552, times=1099511627776)
    
    print(f"\n📌 最终输出的数是: {results[-1]}")
    
    # 分析结果
    analyze_results(results, low, high)
    
    # 启动查找功能
    search_in_results(results)
