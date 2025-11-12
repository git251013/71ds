#!/bin/bash

echo "=== Bitcoin Search Test Run ==="

# 检查可执行文件
if [ ! -f "bitcoin_search" ]; then
    echo "错误: 未找到可执行文件，请先编译"
    exit 1
fi

# 测试参数
START_RANGE=970436974004923190478
END_RANGE=970436974004923190578  # 小范围测试
SAMPLE_SIZE=100

echo "测试范围: $START_RANGE 到 $END_RANGE"
echo "样本大小: $SAMPLE_SIZE 个密钥"

# 运行测试
./bitcoin_search 2>&1 | head -20

echo -e "\n测试完成"
