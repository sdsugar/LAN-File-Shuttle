@echo off
chcp 65001 >nul
title 局域网点对点临时文件传输工具 - 启动中...

echo ========================================================
echo   正在启动: 局域网点对点临时文件传输工具 (LAN File Shuttle)
echo ========================================================

:: 检查 Python 是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python 环境，请先安装 Python 3.8+ 并添加至系统环境变量 PATH。
    pause
    exit /b 1
)

:: 启动应用程序
echo [提示] 正在启动 FastAPI 服务...
python main.py

pause
