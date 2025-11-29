import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from pathlib import Path
import threading
import traceback
import socket
import urllib.request
import sys
import weakref
import warnings
import json
import struct

# 在导入qbittorrentapi之前设置stderr过滤器
class FilteredStderr:
    """过滤stderr输出，抑制qbittorrent-api的无害警告"""
    def __init__(self, original_stderr):
        self.original_stderr = original_stderr
        self.buffer = ""
        self.skip_mode = False
        self.skip_count = 0  # 跳过的行数计数器
        self.max_skip_lines = 15  # 最多跳过15行
    
    def write(self, text):
        # 检查是否包含qbittorrent-api的_http_session错误
        text_lower = text.lower()
        text_line = text.strip()
        
        # 综合检查是否是我们要过滤的错误
        # 检查多个关键词组合，确保能捕获所有变体
        is_qb_error = (
            ('exception ignored in' in text_lower and 'request.__del__' in text_lower) or
            ('_http_session' in text and 'attributeerror' in text_lower) or
            ('request.py' in text and '_trigger_session_initialization' in text) or
            ('client' in text_lower and 'object has no attribute' in text_lower and '_http_session' in text)
        )
        
        # 检查是否是Exception ignored in: <function Request.__del__
        if 'exception ignored in' in text_lower:
            if 'request.__del__' in text_lower:
                # 进入跳过模式
                self.skip_mode = True
                self.skip_count = 0
                return  # 跳过这一行
        
        # 如果正在跳过模式或检测到qbittorrent错误
        if self.skip_mode or is_qb_error:
            if is_qb_error:
                self.skip_mode = True
                
            # 检查是否包含_http_session相关的错误或traceback行
            is_relevant = (
                '_http_session' in text or 
                'attributeerror' in text_lower or
                'qbittorrentapi' in text_lower or
                'request.py' in text or
                'traceback' in text_lower or
                text_line.startswith('File "') or
                text_line.startswith('^') or
                text_line.startswith('AttributeError') or
                text_line == '' or
                "'client' object has no attribute" in text_lower or
                '"client" object has no attribute' in text_lower or
                'client object has no attribute' in text_lower or
                '_trigger_session_initialization' in text
            )
            
            if is_relevant or is_qb_error:
                # 继续跳过
                self.skip_count += 1
                # 如果跳过太多行，强制退出跳过模式（防止误过滤）
                if self.skip_count >= self.max_skip_lines:
                    self.skip_mode = False
                    self.skip_count = 0
                return
            else:
                # 如果遇到不相关的行，退出跳过模式
                self.skip_mode = False
                self.skip_count = 0
        
        # 最终检查：如果包含任何_qbittorrent相关错误关键词，完全忽略
        if any(keyword in text_lower for keyword in [
            '_http_session', 'request.__del__', 'qbittorrentapi/request.py',
            'client object has no attribute', '_trigger_session_initialization'
        ]):
            # 完全忽略这些错误
            return
        
        # 其他输出正常写入
        self.original_stderr.write(text)
    
    def flush(self):
        self.original_stderr.flush()
    
    def __getattr__(self, name):
        return getattr(self.original_stderr, name)

# 在导入qbittorrentapi之前设置stderr过滤器
# 同时设置warnings来过滤警告
import warnings
warnings.filterwarnings('ignore')

_original_stderr = sys.stderr
sys.stderr = FilteredStderr(sys.stderr)

# 现在导入qbittorrentapi
from qbittorrentapi import Client


class QBittorrentUploader:
    def __init__(self, root):
        self.root = root
        self.root.title("qBittorrent 自动上传工具")
        self.root.geometry("700x600")
        
        # 变量
        self.torrent_dir = tk.StringVar()
        self.qb_url = tk.StringVar(value="http://localhost:8080")
        self.qb_username = tk.StringVar()
        self.qb_password = tk.StringVar()
        self.category = tk.StringVar()
        self.client = None
        self.is_connected = False
        
        # 配置文件路径
        self.config_file = os.path.join(os.path.dirname(__file__), "config.json")
        
        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 加载保存的配置
        self.load_config()
        
        self.create_widgets()
    
    def close_connection(self):
        """安全地关闭qBittorrent连接"""
        if self.client is not None:
            try:
                # 尝试登出
                if hasattr(self.client, 'auth_log_out'):
                    self.client.auth_log_out()
            except:
                pass
            
            try:
                # 清理HTTP会话
                if hasattr(self.client, '_http_session') and self.client._http_session is not None:
                    self.client._http_session.close()
            except:
                pass
            
            self.client = None
            self.is_connected = False
    
    def save_config(self):
        """保存配置到文件"""
        try:
            config = {
                'qb_url': self.qb_url.get(),
                'qb_username': self.qb_username.get(),
                # 密码使用base64编码保存（简单加密）
                'qb_password': self.qb_password.get()  # 保存明文密码，也可以使用base64编码
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            self.log(f"配置已保存到: {self.config_file}")
        except Exception as e:
            self.log(f"保存配置失败: {str(e)}")
    
    def load_config(self):
        """从文件加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                if 'qb_url' in config:
                    self.qb_url.set(config['qb_url'])
                if 'qb_username' in config:
                    self.qb_username.set(config['qb_username'])
                if 'qb_password' in config:
                    self.qb_password.set(config['qb_password'])
                
                # 注意：此时日志组件可能还未创建，所以不调用self.log()
        except Exception as e:
            # 配置文件不存在或格式错误，使用默认值
            pass
    
    def refresh_categories(self):
        """从qBittorrent获取分类列表并更新下拉框"""
        if not self.is_connected or not self.client:
            return
        
        try:
            # 获取所有分类
            categories = self.client.torrents_categories()
            
            # 准备下拉框的值列表
            category_list = ['(无分类)']
            if categories:
                # categories是一个字典，键是分类名称
                category_list.extend(sorted(categories.keys()))
            
            # 更新下拉框
            self.category_combo['values'] = category_list
            
            # 如果有保存的分类，尝试选择它
            saved_category = self.category.get()
            if saved_category and saved_category in category_list:
                self.category_combo.current(category_list.index(saved_category))
            else:
                self.category_combo.current(0)  # 默认选择"无分类"
                self.category.set('')
            
            self.log(f"已加载 {len(category_list) - 1} 个分类")
        except Exception as e:
            self.log(f"获取分类列表失败: {str(e)}")
            # 如果获取失败，至少保持"(无分类)"选项
            self.category_combo['values'] = ['(无分类)']
            self.category_combo.current(0)
    
    def on_closing(self):
        """窗口关闭时的清理"""
        # 保存配置
        self.save_config()
        self.close_connection()
        self.root.destroy()
        
    def create_widgets(self):
        # qBittorrent 连接设置框架
        conn_frame = ttk.LabelFrame(self.root, text="qBittorrent 连接设置", padding=10)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(conn_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        url_entry = ttk.Entry(conn_frame, textvariable=self.qb_url, width=40)
        url_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="用户名:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(conn_frame, textvariable=self.qb_username, width=40).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="密码:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(conn_frame, textvariable=self.qb_password, width=40, show="*").grid(row=2, column=1, padx=5, pady=2)
        
        self.connect_btn = ttk.Button(conn_frame, text="连接", command=self.connect_qbittorrent)
        self.connect_btn.grid(row=0, column=2, rowspan=3, padx=5, pady=2)
        
        self.status_label = ttk.Label(conn_frame, text="状态: 未连接", foreground="red")
        self.status_label.grid(row=3, column=0, columnspan=3, pady=5, sticky=tk.W)
        
        # 添加帮助提示
        help_label = ttk.Label(conn_frame, 
                               text="提示: 请确保qBittorrent正在运行且Web UI已启用 (工具→选项→Web UI)", 
                               foreground="gray",
                               font=("Arial", 8))
        help_label.grid(row=4, column=0, columnspan=3, pady=2, sticky=tk.W)
        
        # 上传设置框架
        upload_frame = ttk.LabelFrame(self.root, text="上传设置", padding=10)
        upload_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(upload_frame, text="种子目录:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(upload_frame, textvariable=self.torrent_dir, width=40).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(upload_frame, text="浏览", command=self.browse_directory).grid(row=0, column=2, padx=5, pady=2)
        
        ttk.Label(upload_frame, text="分类 (可选):").grid(row=1, column=0, sticky=tk.W, pady=2)
        # 使用下拉框选择分类，从qBittorrent获取分类列表
        self.category_combo = ttk.Combobox(upload_frame, textvariable=self.category, width=37, state="readonly")
        self.category_combo.grid(row=1, column=1, padx=5, pady=2)
        self.category_combo['values'] = ['(无分类)']  # 默认值
        self.category_combo.current(0)  # 选择第一个选项
        
        # 统计信息显示
        self.stats_label = ttk.Label(upload_frame, text="统计: 未扫描", foreground="blue")
        self.stats_label.grid(row=2, column=0, columnspan=3, pady=5, sticky=tk.W)
        
        # 操作按钮
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.scan_btn = ttk.Button(btn_frame, text="扫描种子文件", command=self.scan_torrents, state=tk.DISABLED)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.upload_btn = ttk.Button(btn_frame, text="开始上传", command=self.start_upload, state=tk.DISABLED)
        self.upload_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # 种子文件列表
        list_frame = ttk.LabelFrame(self.root, text="种子文件列表", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 创建树形视图
        columns = ("文件名", "路径", "种子大小", "内容大小")
        self.torrent_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        # 设置列标题和宽度
        column_widths = [200, 300, 100, 120]
        for idx, col in enumerate(columns):
            self.torrent_tree.heading(col, text=col)
            if idx < len(column_widths):
                self.torrent_tree.column(col, width=column_widths[idx])
            else:
                self.torrent_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.torrent_tree.yview)
        self.torrent_tree.configure(yscrollcommand=scrollbar.set)
        
        self.torrent_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 日志输出
        log_frame = ttk.LabelFrame(self.root, text="日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 进度条框架（添加到最底部）
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 进度状态标签
        self.progress_status_label = ttk.Label(progress_frame, text="就绪", foreground="gray")
        self.progress_status_label.pack(side=tk.LEFT, padx=5)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=self.progress_var, 
            maximum=100, 
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # 进度百分比标签
        self.progress_percent_label = ttk.Label(progress_frame, text="0%", width=6)
        self.progress_percent_label.pack(side=tk.LEFT, padx=5)
        
        # 存储种子文件列表
        self.torrent_files = []
        
    def log(self, message):
        """在日志区域添加消息"""
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
    
    def update_progress(self, current, total, status=""):
        """更新进度条"""
        if total > 0:
            percent = (current / total) * 100
            self.progress_var.set(percent)
            self.progress_percent_label.config(text=f"{percent:.1f}%")
            
            if status:
                self.progress_status_label.config(text=status, foreground="blue")
        else:
            self.progress_var.set(0)
            self.progress_percent_label.config(text="0%")
            if status:
                self.progress_status_label.config(text=status, foreground="gray")
        
        self.root.update_idletasks()
    
    def reset_progress(self):
        """重置进度条"""
        self.progress_var.set(0)
        self.progress_percent_label.config(text="0%")
        self.progress_status_label.config(text="就绪", foreground="gray")
        
    def browse_directory(self):
        """浏览选择目录"""
        directory = filedialog.askdirectory(title="选择包含种子文件的目录")
        if directory:
            self.torrent_dir.set(directory)
            self.log(f"已选择目录: {directory}")
            
    def connect_qbittorrent(self):
        """连接到qBittorrent"""
        def connect_thread():
            # 先关闭旧的连接
            self.close_connection()
            
            try:
                url = self.qb_url.get().strip()
                username = self.qb_username.get().strip()
                password = self.qb_password.get().strip()
                
                if not url:
                    self.root.after(0, lambda: messagebox.showerror("错误", "请输入qBittorrent URL"))
                    return
                
                self.log(f"正在连接到 {url}...")
                self.root.after(0, lambda: self.status_label.config(text="状态: 正在连接...", foreground="orange"))
                
                # 解析URL，提取host和port
                # 支持格式: http://localhost:8080, https://localhost:8080, localhost:8080
                # qbittorrent-api库的Client只支持host和port参数，不支持url参数
                url_clean = url.replace('http://', '').replace('https://', '')
                
                if ':' in url_clean:
                    host, port_str = url_clean.split(':', 1)
                    try:
                        port = int(port_str)
                    except:
                        port = 8080
                else:
                    host = url_clean
                    port = 8080
                
                self.log(f"解析地址: {host}:{port}")
                
                # 创建客户端，使用host和port参数（不支持url参数）
                try:
                    client = Client(
                        host=host, 
                        port=port, 
                        VERIFY_WEBUI_CERTIFICATE=False
                    )
                    self.log("✓ Client对象创建成功")
                except Exception as create_error:
                    error_str = str(create_error)
                    self.log(f"创建Client对象失败: {error_str}")
                    raise create_error
                
                # 只有在成功创建后才赋值给self.client
                self.client = client
                
                # 根据官方API文档: POST /api/v2/auth/login
                # 使用username和password参数进行登录
                # 必须先登录才能访问其他API
                
                # 首先尝试登录（如果需要）
                login_success = False
                
                if username or password:
                    # 提供了用户名或密码，尝试登录
                    login_username = username if username else ''
                    login_password = password if password else ''
                    
                    self.log(f"尝试登录...")
                    self.log(f"  连接地址: {host}:{port}")
                    self.log(f"  用户名: {login_username or '(未设置)'}")
                    self.log(f"  密码: {'*' * len(login_password) if login_password else '(未设置)'}")
                    
                    try:
                        # qbittorrent-api库的登录方法
                        # 根据官方API文档，这会发送POST请求到 /api/v2/auth/login
                        # 使用Content-Type: application/x-www-form-urlencoded格式
                        # 确保username和password是字符串类型，不为None
                        if not login_username:
                            login_username = ''
                        if not login_password:
                            login_password = ''
                        
                        self.log(f"发送登录请求到 {host}:{port}...")
                        self.client.auth_log_in(
                            username=login_username,
                            password=login_password
                        )
                        login_success = True
                        self.log("✓ 登录成功")
                    except Exception as login_error:
                        error_str = str(login_error)
                        error_type = type(login_error).__name__
                        self.log(f"✗ 登录失败 ({error_type}): {error_str}")
                        
                        # 检查是否是LoginFailed异常（qbittorrent-api库的特定异常）
                        if error_type == "LoginFailed" or "LoginFailed" in str(type(login_error)):
                            # LoginFailed通常是用户名或密码错误
                            raise Exception(
                                f"登录失败: 用户名或密码错误。\n\n"
                                f"请检查:\n"
                                f"1. qBittorrent WebUI的用户名是否正确（当前: {username or '(未设置)'}）\n"
                                f"2. qBittorrent WebUI的密码是否正确\n"
                                f"3. qBittorrent WebUI是否已启用认证\n"
                                f"4. 在qBittorrent中: 工具 → 选项 → Web UI → 检查用户名和密码\n\n"
                                f"连接地址: {host}:{port}\n"
                                f"错误类型: {error_type}\n"
                                f"详细错误: {error_str}"
                            )
                        # 检查是否是认证错误
                        elif "401" in error_str or "Unauthorized" in error_str or "forbidden" in error_str.lower():
                            raise Exception(
                                f"认证失败: 用户名或密码错误。\n\n"
                                f"请检查:\n"
                                f"1. qBittorrent WebUI是否已启用认证\n"
                                f"2. 用户名和密码是否正确\n"
                                f"3. WebUI设置中的用户名和密码\n\n"
                                f"连接地址: {host}:{port}\n"
                                f"错误详情: {error_str}"
                            )
                        elif "connection" in error_str.lower() or "refused" in error_str.lower() or "timeout" in error_str.lower():
                            raise Exception(
                                f"连接失败: 无法连接到qBittorrent WebUI。\n\n"
                                f"请检查:\n"
                                f"1. qBittorrent是否正在运行\n"
                                f"2. WebUI是否已启用\n"
                                f"3. URL和端口是否正确（当前: {host}:{port}）\n"
                                f"4. 防火墙是否允许连接\n"
                                f"5. 网络连接是否正常\n\n"
                                f"错误详情: {error_str}"
                            )
                        else:
                            # 其他错误，提供更详细的信息
                            raise Exception(
                                f"登录时发生错误。\n\n"
                                f"错误类型: {error_type}\n"
                                f"错误信息: {error_str}\n\n"
                                f"请检查:\n"
                                f"1. qBittorrent WebUI是否正在运行\n"
                                f"2. 用户名和密码是否正确\n"
                                f"3. 连接地址是否正确 ({host}:{port})\n\n"
                                f"请查看日志获取更多详细信息。"
                            )
                else:
                    # 未提供用户名和密码
                    self.log("未提供用户名和密码，尝试无认证连接...")
                    # 不登录，直接尝试访问API来测试是否需要认证
                    login_success = True  # 假设不需要登录
                
                # 验证连接 - 获取版本信息
                # 这会验证登录是否成功以及连接是否正常
                self.log("验证连接...")
                try:
                    version = self.client.app_version()
                    self.log(f"✓ 连接成功，qBittorrent版本: {version}")
                    self.is_connected = True
                    
                    # 连接成功后保存配置
                    self.save_config()
                    
                    # 获取分类列表并更新下拉框
                    self.log("获取分类列表...")
                    self.refresh_categories()
                except Exception as verify_error:
                    error_str = str(verify_error)
                    # 如果是401错误且没有登录，说明需要登录
                    if ("401" in error_str or "Unauthorized" in error_str) and not (username or password):
                        raise Exception("WebUI已启用认证，但未提供用户名和密码。\n\n请在连接设置中输入qBittorrent WebUI的用户名和密码。")
                    elif ("401" in error_str or "Unauthorized" in error_str) and (username or password):
                        raise Exception("认证失败，用户名或密码可能错误。\n\n请检查:\n1. 用户名和密码是否正确\n2. qBittorrent WebUI的认证设置\n\n错误详情: {error_str}")
                    else:
                        raise Exception(f"连接验证失败: {error_str}")
                
                # 获取qBittorrent信息
                try:
                    webui_version = self.client.app_webapiVersion()
                    self.log(f"Web API 版本: {webui_version}")
                except:
                    pass
                
                self.root.after(0, lambda: self.status_label.config(text=f"状态: 已连接 (版本: {version})", foreground="green"))
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.upload_btn.config(state=tk.NORMAL))
                
                self.log(f"✓ 成功连接到 qBittorrent (版本: {version})")
                
            except Exception as e:
                self.is_connected = False
                
                # 清理未完全初始化的client对象
                # 使用弱引用避免循环引用导致的问题
                temp_client = self.client
                self.client = None  # 先清除引用，避免垃圾回收时的问题
                
                # 尝试清理临时client对象
                if temp_client is not None:
                    try:
                        # 尝试登出（这会清理session）
                        if hasattr(temp_client, 'auth_log_out'):
                            try:
                                temp_client.auth_log_out()
                            except:
                                pass
                    except:
                        pass
                
                # 强制垃圾回收，避免延迟清理导致的错误
                import gc
                gc.collect()
                
                error_msg = str(e)
                error_detail = traceback.format_exc()
                self.log(f"✗ 连接失败: {error_msg}")
                
                # 诊断连接问题
                self.log("\n开始诊断连接问题...")
                url_for_diagnose = self.qb_url.get().strip()
                url_for_diagnose = url_for_diagnose.replace('http://', '').replace('https://', '')
                
                if ':' in url_for_diagnose:
                    host, port_str = url_for_diagnose.split(':', 1)
                    try:
                        port = int(port_str)
                    except:
                        port = 8080
                else:
                    host = url_for_diagnose
                    port = 8080
                
                # 检查端口是否开放
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host if host != 'localhost' else '127.0.0.1', port))
                    sock.close()
                    if result == 0:
                        self.log(f"✓ 端口 {port} 已开放")
                    else:
                        self.log(f"✗ 端口 {port} 无法连接，可能是：")
                        self.log(f"  - qBittorrent未运行")
                        self.log(f"  - Web UI未启用")
                        self.log(f"  - 端口号不正确")
                except Exception as diag_e:
                    self.log(f"诊断端口时出错: {str(diag_e)}")
                
                self.log(f"详细错误信息:\n{error_detail}")
                
                # 提供更友好的错误提示
                friendly_msg = error_msg
                suggestions = []
                
                if "401" in error_msg or "Unauthorized" in error_msg or "forbidden" in error_msg.lower():
                    friendly_msg = "认证失败"
                    suggestions = [
                        "请检查用户名和密码是否正确",
                        "如果qBittorrent未设置密码，请留空用户名和密码",
                        "检查qBittorrent的Web UI认证设置"
                    ]
                elif "Connection" in error_msg or "refused" in error_msg.lower() or "10061" in error_msg:
                    friendly_msg = "无法连接到qBittorrent"
                    suggestions = [
                        "1. 确保qBittorrent正在运行",
                        "2. 启用Web UI: 工具 → 选项 → Web UI → 启用Web用户界面",
                        "3. 检查URL和端口是否正确（默认: http://localhost:8080）",
                        "4. 检查防火墙是否阻止了连接",
                        "5. 如果使用Docker，检查端口映射"
                    ]
                elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                    friendly_msg = "连接超时"
                    suggestions = [
                        "1. 检查网络连接",
                        "2. 检查qBittorrent是否正在运行",
                        "3. 如果使用远程连接，检查网络是否可达"
                    ]
                elif "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
                    friendly_msg = "SSL证书问题"
                    suggestions = [
                        "如果使用HTTPS，尝试使用HTTP",
                        "或检查SSL证书配置"
                    ]
                
                suggestion_text = "\n".join(suggestions) if suggestions else "请检查日志获取详细信息"
                
                full_error_msg = f"{friendly_msg}\n\n建议:\n{suggestion_text}\n\n详细错误: {error_msg}"
                
                self.root.after(0, lambda: messagebox.showerror("连接失败", full_error_msg))
                self.root.after(0, lambda: self.status_label.config(text="状态: 连接失败", foreground="red"))
        
        threading.Thread(target=connect_thread, daemon=True).start()
        
    def scan_torrents(self):
        """扫描目录中的种子文件"""
        directory = self.torrent_dir.get().strip()
        
        if not directory:
            messagebox.showerror("错误", "请先选择目录")
            return
            
        if not os.path.isdir(directory):
            messagebox.showerror("错误", "所选路径不是有效目录")
            return
        
        # 清空现有列表
        for item in self.torrent_tree.get_children():
            self.torrent_tree.delete(item)
        self.torrent_files.clear()
        
        self.log(f"开始扫描目录: {directory}")
        
        # 扫描所有.torrent文件
        torrent_count = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.torrent'):
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    size_str = self.format_size(file_size)
                    
                    # 添加到树形视图（先显示文件大小，后面会更新为内容大小）
                    self.torrent_tree.insert("", tk.END, values=(file, file_path, size_str, "解析中..."))
                    
                    # 保存到列表
                    self.torrent_files.append({
                        'name': file,
                        'path': file_path,
                        'size': file_size,  # 种子文件本身的大小
                        'content_size': 0   # 内容大小，稍后解析
                    })
                    torrent_count += 1
        
        # 解析torrent文件获取内容大小
        self.log("正在解析种子文件内容大小...")
        self.update_progress(0, torrent_count, "解析种子文件内容大小...")
        total_content_size = 0
        parsed_count = 0
        
        # 获取所有树形视图项
        tree_items = list(self.torrent_tree.get_children())
        
        for idx, torrent in enumerate(self.torrent_files):
            try:
                content_size = self.get_torrent_content_size(torrent['path'])
                if content_size > 0:
                    torrent['content_size'] = content_size
                    total_content_size += content_size
                    parsed_count += 1
                    content_size_str = self.format_size(content_size)
                else:
                    torrent['content_size'] = 0
                    content_size_str = "解析失败"
                
                # 更新树形视图中对应的项
                if idx < len(tree_items):
                    item = tree_items[idx]
                    values = list(self.torrent_tree.item(item, 'values'))
                    if len(values) >= 4:
                        values[3] = content_size_str
                    elif len(values) == 3:
                        values.append(content_size_str)
                    self.torrent_tree.item(item, values=values)
                
                # 更新进度条（使用局部变量避免闭包问题）
                current_idx = idx
                current_total = len(self.torrent_files)
                self.root.after(0, lambda i=current_idx, t=current_total: 
                    self.update_progress(i + 1, t, f"解析种子文件: {i + 1}/{t}"))
                
                # 每处理10个或最后一个时更新界面
                if (idx + 1) % 10 == 0 or (idx + 1) == len(self.torrent_files):
                    self.root.update_idletasks()
                    
            except Exception as e:
                torrent['content_size'] = 0
                self.log(f"解析 {torrent['name']} 失败: {str(e)}")
                
                # 更新树形视图显示解析失败
                if idx < len(tree_items):
                    item = tree_items[idx]
                    values = list(self.torrent_tree.item(item, 'values'))
                    if len(values) >= 4:
                        values[3] = "解析失败"
                    elif len(values) == 3:
                        values.append("解析失败")
                    self.torrent_tree.item(item, values=values)
        
        # 更新统计信息显示
        size_str = self.format_size(total_content_size)
        self.stats_label.config(
            text=f"统计: 共 {torrent_count} 个种子文件，内容总大小: {size_str}",
            foreground="blue"
        )
        
        # 完成进度
        self.update_progress(torrent_count, torrent_count, "解析完成!")
        
        self.log(f"扫描完成，找到 {torrent_count} 个种子文件")
        self.log(f"内容总大小: {size_str} (成功解析 {parsed_count}/{torrent_count} 个)")
        
    def get_torrent_content_size(self, torrent_path):
        """解析torrent文件获取内容总大小"""
        try:
            with open(torrent_path, 'rb') as f:
                torrent_data = f.read()
            
            # 解析Bencode格式
            decoded, _ = self.bdecode(torrent_data)
            
            if isinstance(decoded, dict):
                info = decoded.get(b'info', {})
                
                # 检查是否是单文件torrent
                if b'length' in info:
                    # 单文件
                    return info[b'length']
                elif b'files' in info:
                    # 多文件
                    total_size = 0
                    for file_info in info[b'files']:
                        if b'length' in file_info:
                            total_size += file_info[b'length']
                    return total_size
            
            return 0
        except Exception as e:
            # 解析失败，返回0
            return 0
    
    def bdecode(self, data, offset=0):
        """简单的Bencode解码器"""
        if offset >= len(data):
            return None, offset
        
        byte_val = data[offset:offset+1]
        
        if byte_val == b'd':  # dictionary
            offset += 1
            result = {}
            while offset < len(data) and data[offset:offset+1] != b'e':
                key, offset = self.bdecode(data, offset)
                if key is None or offset >= len(data):
                    break
                value, offset = self.bdecode(data, offset)
                if value is None or offset >= len(data):
                    break
                result[key] = value
            if offset < len(data) and data[offset:offset+1] == b'e':
                offset += 1
            return result, offset
        elif byte_val == b'l':  # list
            offset += 1
            result = []
            while offset < len(data) and data[offset:offset+1] != b'e':
                item, offset = self.bdecode(data, offset)
                if item is None or offset >= len(data):
                    break
                result.append(item)
            if offset < len(data) and data[offset:offset+1] == b'e':
                offset += 1
            return result, offset
        elif byte_val == b'i':  # integer
            offset += 1
            end = data.find(b'e', offset)
            if end == -1:
                return None, offset
            try:
                value = int(data[offset:end])
                return value, end + 1
            except:
                return None, offset
        else:
            # 尝试解析字符串 (格式: length:string)
            # 检查是否是数字开头
            colon = data.find(b':', offset)
            if colon == -1:
                return None, offset
            
            # 检查offset到colon之间是否都是数字
            try:
                length_str = data[offset:colon].decode('ascii')
                length = int(length_str)
            except:
                return None, offset
            
            offset = colon + 1
            if offset + length > len(data):
                return None, offset
            
            value = data[offset:offset+length]
            offset += length
            return value, offset
    
    def format_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
        
    def start_upload(self):
        """开始上传种子文件"""
        if not self.is_connected:
            messagebox.showerror("错误", "请先连接到qBittorrent")
            return
            
        if not self.torrent_files:
            messagebox.showerror("错误", "请先扫描种子文件")
            return
        
        # 获取选择的分类，如果是"(无分类)"则设置为None
        category = self.category.get().strip()
        if category == '(无分类)' or not category:
            category = None
        
        def upload_thread():
            total_files = len(self.torrent_files)
            self.log(f"\n开始上传 {total_files} 个种子文件...")
            if category:
                self.log(f"使用分类: {category}")
            
            # 初始化进度条
            self.root.after(0, lambda: self.update_progress(0, total_files, "准备上传..."))
            
            success_count = 0
            fail_count = 0
            
            for idx, torrent in enumerate(self.torrent_files, 1):
                try:
                    file_path = torrent['path']
                    file_name = torrent['name']
                    
                    # 更新进度条（使用局部变量避免闭包问题）
                    current_idx = idx
                    current_total = total_files
                    current_name = file_name
                    self.root.after(0, lambda i=current_idx, t=current_total, n=current_name: 
                        self.update_progress(i - 1, t, f"上传: {n}"))
                    
                    self.log(f"[{idx}/{total_files}] 上传: {file_name}")
                    
                    # 上传到qBittorrent
                    # 根据官方API文档: POST /api/v2/torrents/add
                    # 使用multipart/form-data格式上传torrent文件
                    # category参数用于指定分类（可选）
                    add_params = {
                        'torrent_files': [file_path]
                    }
                    
                    if category:
                        add_params['category'] = category
                    
                    # 调用API添加torrent
                    self.client.torrents_add(**add_params)
                    
                    success_count += 1
                    self.log(f"  ✓ 成功: {file_name}")
                    
                except Exception as e:
                    fail_count += 1
                    error_msg = f"  ✗ 失败: {file_name} - {str(e)}"
                    self.log(error_msg)
                    print(traceback.format_exc())
                
                # 更新进度（使用局部变量避免闭包问题）
                current_idx = idx
                current_total = total_files
                self.root.after(0, lambda i=current_idx, t=current_total: 
                    self.update_progress(i, t, f"上传进度: {i}/{t}"))
            
            # 完成进度
            self.root.after(0, lambda: self.update_progress(total_files, total_files, "上传完成!"))
            
            self.log(f"\n上传完成! 成功: {success_count}, 失败: {fail_count}")
            self.root.after(0, lambda: messagebox.showinfo("完成", 
                f"上传完成!\n成功: {success_count}\n失败: {fail_count}"))
        
        # 禁用上传按钮，防止重复上传
        self.upload_btn.config(state=tk.DISABLED)
        
        def upload_with_re_enable():
            upload_thread()
            # 上传完成后重新启用按钮
            self.root.after(0, lambda: self.upload_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=upload_with_re_enable, daemon=True).start()


def suppress_qbittorrentapi_warnings():
    """抑制qbittorrent-api库在垃圾回收时的无害警告"""
    # stderr过滤器已经在导入时设置
    # 设置warnings过滤器（只过滤Warning类的消息，AttributeError不是Warning的子类）
    warnings.filterwarnings('ignore', message='.*_http_session.*')
    
    # 在程序退出时确保过滤器仍然有效
    import atexit
    def ensure_filter_on_exit():
        # 确保stderr过滤器在退出时仍然有效
        if not isinstance(sys.stderr, FilteredStderr):
            try:
                sys.stderr = FilteredStderr(_original_stderr)
            except:
                pass
    atexit.register(ensure_filter_on_exit)


def main():
    # 抑制qbittorrent-api的警告
    suppress_qbittorrentapi_warnings()
    
    root = tk.Tk()
    app = QBittorrentUploader(root)
    root.mainloop()


if __name__ == "__main__":
    main()

