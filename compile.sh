#!/bin/bash

echo "=== Bitcoin Private Key Search Compilation ==="

# 检查CUDA
if ! command -v nvcc &> /dev/null; then
    echo "错误: 未找到nvcc，请先安装CUDA工具包"
    exit 1
fi

echo "CUDA版本:"
nvcc --version

echo "GPU信息:"
nvidia-smi

# 编译参数
NVCC_FLAGS="-O3 -std=c++14 -arch=sm_70"
SOURCE="bitcoin_search.cu"
OUTPUT="bitcoin_search"

echo "开始编译..."
nvcc $NVCC_FLAGS $SOURCE -o $OUTPUT

if [ $? -eq 0 ]; then
    echo "✅ 编译成功!"
    echo "生成的可执行文件: $OUTPUT"
    
    # 显示文件信息
    echo -e "\n文件信息:"
    ls -lh $OUTPUT
    
    # 测试运行
    echo -e "\n测试运行:"
    ./$OUTPUT --help 2>/dev/null || echo "程序准备就绪"
else
    echo "❌ 编译失败!"
    exit 1
fi
