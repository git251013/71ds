#!/bin/bash

echo "=== GPU监控 ==="
nvidia-smi

echo -e "\n=== 系统信息 ==="
free -h
echo "CPU使用率:"
mpstat 1 1 | grep -A 5 "%idle"

echo -e "\n=== 进程监控 ==="
ps aux | grep bitcoin_search | grep -v grep
