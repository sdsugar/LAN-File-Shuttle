#!/usr/bin/env bash

echo "========================================================"
echo "  正在启动: 局域网点对点临时文件传输工具 (LAN File Shuttle)"
echo "========================================================"

# 检测 python3 或 python
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
else
    echo "[错误] 未检测到 Python 环境，请先安装 Python 3.8+"
    exit 1
fi

echo "[提示] 使用 Python: $($PY_BIN --version)"
$PY_BIN main.py "$@"
