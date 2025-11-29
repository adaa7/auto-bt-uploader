@echo off
chcp 65001 >nul
title qBittorrent 自动上传工具

REM 获取脚本所在目录
cd /d "%~dp0"

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未检测到Python，请先安装Python
    echo.
    pause
    exit /b 1
)

REM 检查main.py是否存在
if not exist "main.py" (
    echo 错误: 找不到 main.py 文件
    echo.
    pause
    exit /b 1
)

REM 运行程序
echo 正在启动 qBittorrent 自动上传工具...
echo.
python main.py

REM 如果程序异常退出，暂停以便查看错误信息
if errorlevel 1 (
    echo.
    echo 程序异常退出，错误代码: %errorlevel%
    pause
)

