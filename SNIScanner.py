import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import socket
import time
import json
import re
import ipaddress
import os
import csv
import ssl
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

# ====== دیتابیس‌های داخلی (هوشمندی شبکه) ======
CDN_PREFIXES = {
    "Cloudflare":["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69."],
    "Vercel":["76.76.", "66.33.", "216.230.", "198.169."],
    "Fastly":["151.101.", "199.232.", "146.75."],
    "Akamai":["23.", "96.", "124.", "125.", "184.", "203.", "205.", "212."],
    "Google Cloud":["34.", "35.", "104.15.", "130.211."],
    "AWS": ["18.", "52.", "54.", "3.", "13."]
}

FALLBACK_DNS = {
    "cloudflare.com":["104.16.132.229", "104.16.133.229"],
    "vercel.com":["76.76.21.21", "198.169.2.193"],
    "nextjs.org":["216.230.86.65"],
    "npmjs.com":["104.17.134.117"],
    "react.dev": ["66.33.60.193"],
}

class SNIScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("اسکنر و رادار پیشرفته SNI (نسخه Enterprise)")
        self.root.geometry("1150x800")
        
        self.is_dark = False
        
        self.font_main = ("Tahoma", 9)
        self.font_bold = ("Tahoma", 9, "bold")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.is_scanning = False
        self.executor = None
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # متغیرهای آماری
        self.stat_total = 0
        self.stat_checked = 0
        self.stat_success = 0
        self.stat_ping_only = 0
        self.stat_down = 0
        
        self.setup_ui()
        self.apply_theme()
        self.root.after(100, self.process_queue)

    def setup_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        # ====== پنل راست (تنظیمات و ورودی) ======
        self.right_panel = ttk.Frame(self.root)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.right_panel.columnconfigure(0, weight=1)

        header_frame = ttk.Frame(self.right_panel)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header_frame.columnconfigure(0, weight=1)
        
        self.btn_theme = ttk.Button(header_frame, text="🌙 حالت تاریک", command=self.toggle_theme, width=15)
        self.btn_theme.grid(row=0, column=0, sticky="w")
        
        lbl_input = ttk.Label(header_frame, text=":ورودی (دامنه‌، آی‌پی، رنج CIDR)", font=self.font_bold)
        lbl_input.grid(row=0, column=1, sticky="e")

        self.text_input = tk.Text(self.right_panel, width=40, height=10, font=("Consolas", 10))
        self.text_input.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.right_panel.rowconfigure(1, weight=1)

        # ====== پنل تنظیمات ======
        self.settings_frame = ttk.LabelFrame(self.right_panel, text=" تنظیمات رادار شبکه ", padding=10)
        self.settings_frame.grid(row=2, column=0, sticky="nsew")
        self.settings_frame.columnconfigure(1, weight=1)

        row_idx = 0
        self.default_sni_var = tk.StringVar(value="yahoo.com")
        ttk.Entry(self.settings_frame, textvariable=self.default_sni_var, justify="left").grid(row=row_idx, column=0, sticky="ew", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":SNI پیش‌فرض (برای آی‌پی/رنج)").grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)
        
        row_idx += 1
        self.ports_var = tk.StringVar(value="443, 8443, 2053")
        ttk.Entry(self.settings_frame, textvariable=self.ports_var, justify="left").grid(row=row_idx, column=0, sticky="ew", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":پورت‌های هدف").grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.cidr_limit_var = tk.IntVar(value=256)
        ttk.Entry(self.settings_frame, textvariable=self.cidr_limit_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":حداکثر بسط رنج (Max CIDR)").grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.threads_var = tk.IntVar(value=15)
        ttk.Entry(self.settings_frame, textvariable=self.threads_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":سرعت اسکن (Threads)").grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Entry(self.settings_frame, textvariable=self.timeout_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":(Timeout) زمان انتظار").grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.strict_ping_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.settings_frame, text="حالت سخت‌گیرانه (الزام پینگ ICMP + باز بودن پورت)", variable=self.strict_ping_var).grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.smart_ip_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="فیلتر آی‌پی‌های Private (داخلی/نامعتبر)", variable=self.smart_ip_var).grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="ذخیره خودکار بهترین کانفیگ", variable=self.auto_save_var).grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        # دکمه‌های کنترل
        btn_frame = ttk.Frame(self.right_panel)
        btn_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self.btn_start = ttk.Button(btn_frame, text="شروع رادار", command=self.start_scan)
        self.btn_start.grid(row=0, column=1, sticky="nsew", padx=2)

        self.btn_stop = ttk.Button(btn_frame, text="توقف", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=0, sticky="nsew", padx=2)

        # ====== پنل چپ (نتایج و آمار) ======
        self.left_panel = ttk.Frame(self.root)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.left_panel.columnconfigure(0, weight=1)
        self.left_panel.rowconfigure(2, weight=1)

        # 1. داشبورد آمار زنده
        self.dash_frame = tk.Frame(self.left_panel, bg="#f8f9fa")
        self.dash_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.lbl_stat_total = self.create_metric_card(self.dash_frame, "بررسی شده", "#e9ecef", "#495057")
        self.lbl_stat_success = self.create_metric_card(self.dash_frame, "موفق (SNI/TCP)", "#d1e7dd", "#0f5132")
        self.lbl_stat_ping = self.create_metric_card(self.dash_frame, "فقط پینگ", "#cff4fc", "#055160")
        self.lbl_stat_down = self.create_metric_card(self.dash_frame, "ناموفق / مسدود", "#f8d7da", "#842029")

        # 2. ابزارهای بالای جدول
        tools_frame = ttk.Frame(self.left_panel)
        tools_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        
        self.btn_export = ttk.Button(tools_frame, text="ساخت config.json", style="Success.TButton", command=self.export_config)
        self.btn_export.pack(side="left", padx=2)
        
        self.btn_export_csv = ttk.Button(tools_frame, text="خروجی گروهی (CSV)", command=self.export_csv)
        self.btn_export_csv.pack(side="left", padx=2)
        
        btn_sort = ttk.Button(tools_frame, text="مرتب‌سازی نتایج", command=self.sort_results)
        btn_sort.pack(side="left", padx=2)

        self.lbl_results = ttk.Label(tools_frame, text="برای انتخاب خروجی کلیک کنید (☑)", font=("Tahoma", 8))
        self.lbl_results.pack(side="right")

        # 3. جدول نتایج
        columns = ("select", "target", "ip", "port", "ping", "sni", "cdn", "speed", "status")
        self.tree = ttk.Treeview(self.left_panel, columns=columns, show="headings")
        
        self.tree.heading("select", text="تیک")
        self.tree.heading("target", text="تارگت (ورودی)")
        self.tree.heading("ip", text="آی‌پی تست شده")
        self.tree.heading("port", text="پورت")
        self.tree.heading("ping", text="پینگ ICMP")
        self.tree.heading("sni", text="هندشیک SNI")
        self.tree.heading("cdn", text="تأمین‌کننده (CDN)")
        self.tree.heading("speed", text="سرعت")
        self.tree.heading("status", text="نتیجه نهایی")
        
        self.tree.column("select", width=40, anchor="center")
        self.tree.column("target", width=120, anchor="w")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("port", width=50, anchor="center")
        self.tree.column("ping", width=75, anchor="center")
        self.tree.column("sni", width=80, anchor="center")
        self.tree.column("cdn", width=110, anchor="center")
        self.tree.column("speed", width=80, anchor="center")
        self.tree.column("status", width=90, anchor="center")

        self.tree.grid(row=2, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(self.left_panel, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=2, column=1, sticky='ns')

        self.tree.bind('<ButtonRelease-1>', self.toggle_check)

        self.lbl_status = ttk.Label(self.left_panel, text="رادار آماده اسکن شبکه است...")
        self.lbl_status.grid(row=3, column=0, sticky="e", pady=5)

    def create_metric_card(self, parent, title, bg_color, fg_color):
        frame = tk.Frame(parent, bg=bg_color, bd=1, relief="ridge")
        frame.pack(side="left", fill="both", expand=True, padx=3)
        lbl_val = tk.Label(frame, text="0", font=("Consolas", 15, "bold"), bg=bg_color, fg=fg_color)
        lbl_val.pack(pady=(8,0))
        lbl_title = tk.Label(frame, text=title, font=("Tahoma", 8, "bold"), bg=bg_color, fg=fg_color)
        lbl_title.pack(pady=(0,8))
        return lbl_val

    def update_metrics_ui(self):
        self.lbl_stat_total.configure(text=f"{self.stat_checked} / {self.stat_total}")
        self.lbl_stat_success.configure(text=str(self.stat_success))
        self.lbl_stat_ping.configure(text=str(self.stat_ping_only))
        self.lbl_stat_down.configure(text=str(self.stat_down))

    def apply_theme(self):
        if self.is_dark:
            bg_color = "#212529"
            fg_color = "#f8f9fa"
            tree_bg = "#343a40"
            tree_fg = "#f8f9fa"
            input_bg = "#495057"
            self.btn_theme.configure(text="☀️ حالت روشن")
            self.lbl_results.configure(foreground="#6ea8fe")
            self.lbl_status.configure(foreground="#adb5bd")
            self.dash_frame.configure(bg=bg_color)
        else:
            bg_color = "#f8f9fa"
            fg_color = "#212529"
            tree_bg = "white"
            tree_fg = "#212529"
            input_bg = "white"
            self.btn_theme.configure(text="🌙 حالت تاریک")
            self.lbl_results.configure(foreground="#0d6efd")
            self.lbl_status.configure(foreground="#6c757d")
            self.dash_frame.configure(bg=bg_color)

        self.root.configure(bg=bg_color)
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        
        self.style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg)
        self.text_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def toggle_check(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            if column == '#1': 
                clicked_item = self.tree.identify_row(event.y)
                if not clicked_item: return
                self._check_item(clicked_item)

    def _check_item(self, item_id):
        for child in self.tree.get_children():
            vals = list(self.tree.item(child, "values"))
            if child == item_id:
                vals[0] = "☑" if vals[0] == "☐" else "☐"
            else:
                vals[0] = "☐"
            self.tree.item(child, values=vals)

    def is_valid_ip(self, ip_str):
        if not self.smart_ip_var.get(): return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or not ip_obj.is_global:
                return False
            return True
        except ValueError:
            return False

    def detect_cdn(self, ip_str):
        for cdn_name, prefixes in CDN_PREFIXES.items():
            for prefix in prefixes:
                if ip_str.startswith(prefix):
                    return cdn_name
        return "Unknown"

    def icmp_ping(self, ip, timeout):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        t_param = '-w' if platform.system().lower() == 'windows' else '-W'
        t_val = str(int(timeout * 1000)) if platform.system().lower() == 'windows' else str(max(1, int(timeout)))
        cmd = ['ping', param, '1', t_param, t_val, ip]
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            if res.returncode == 0:
                match = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)', res.stdout, re.IGNORECASE)
                if match: return True, float(match.group(1))
                return True, 1.0 # پینگ زیر ۱ میلی‌ثانیه
        except Exception:
            pass
        return False, None

    def measure_speed(self, ip, port, sni, timeout):
        try:
            start = time.time()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                if port in[443, 8443, 2053, 2083, 2087, 2096]:
                    with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                        req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(req.encode())
                        bytes_recv = 0
                        while True:
                            data = ssock.recv(4096)
                            if not data: break
                            bytes_recv += len(data)
                            if time.time() - start > 1.0: break
                else:
                    req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                    sock.sendall(req.encode())
                    bytes_recv = 0
                    while True:
                        data = sock.recv(4096)
                        if not data: break
                        bytes_recv += len(data)
                        if time.time() - start > 1.0: break

            duration = max(time.time() - start, 0.001)
            return round((bytes_recv / 1024) / duration, 1)
        except Exception:
            return 0.0

    def scan_worker(self, task):
        if self.stop_event.is_set(): return
        
        target_label, test_host, sni_to_use, port = task
        timeout_val = self.timeout_var.get()
        strict_ping = self.strict_ping_var.get()

        # مرحله 1: حل کردن DNS (اگر test_host دامنه باشد)
        ips_to_test =[]
        try:
            ipaddress.ip_address(test_host)
            ips_to_test = [test_host]
        except ValueError:
            try:
                _, _, resolved = socket.gethostbyname_ex(test_host)
                ips_to_test.extend(resolved)
            except Exception:
                # سیستم ضد فیلتر DNS
                if test_host in FALLBACK_DNS:
                    ips_to_test.extend(FALLBACK_DNS[test_host])

        valid_ips = list(set([ip for ip in ips_to_test if self.is_valid_ip(ip)]))
        
        if not valid_ips:
            self.result_queue.put({
                'target': target_label, 'ip': '-', 'port': port, 'ping': '-', 
                'sni': '-', 'cdn': '-', 'speed': '-', 'status': 'DNS Error/Private', 'cat': 'down'
            })
            return

        for ip in valid_ips:
            if self.stop_event.is_set(): return
            
            cdn_name = self.detect_cdn(ip)
            
            # 1. پینگ ICMP
            ping_ok, ping_ms = self.icmp_ping(ip, timeout_val)
            
            # اگر در حالت سخت‌گیرانه پینگ نداشت، دراپ کن
            if strict_ping and not ping_ok:
                self.result_queue.put({
                    'target': target_label, 'ip': ip, 'port': port, 'ping': 'Timeout', 
                    'sni': '-', 'cdn': cdn_name, 'speed': '-', 'status': '✖ Filtered (Strict)', 'cat': 'down'
                })
                continue

            # 2. بررسی اتصال TCP و هندشیک SNI
            tcp_ok = False
            tls_ok = False
            try:
                with socket.create_connection((ip, port), timeout=timeout_val) as sock:
                    tcp_ok = True
                    # بررسی واقعی SNI
                    if port in[443, 8443, 2053, 2083, 2087, 2096]:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with ctx.wrap_socket(sock, server_hostname=sni_to_use):
                            tls_ok = True
            except Exception:
                pass

            # 3. محاسبه سرعت و نتیجه‌گیری
            speed_kb = "-"
            status = ""
            cat = ""

            if tls_ok:
                speed_kb = f"{self.measure_speed(ip, port, sni_to_use, timeout_val)} KB/s"
                status = "✔ SNI Usable"
                cat = "success"
            elif tcp_ok:
                status = "✔ TCP OK"
                cat = "success"
            elif ping_ok:
                status = "◐ Ping Only"
                cat = "ping_only"
            else:
                status = "✖ Down"
                cat = "down"

            self.result_queue.put({
                'target': target_label, 'ip': ip, 'port': port, 
                'ping': f"{ping_ms} ms" if ping_ok else "Timeout", 
                'sni': 'Valid' if tls_ok else ('Failed' if tcp_ok else '-'), 
                'cdn': cdn_name, 'speed': speed_kb, 'status': status, 'cat': cat, 'sni_used': sni_to_use
            })

    def start_scan(self):
        raw_lines = self.text_input.get("1.0", tk.END).strip().split('\n')
        default_sni = self.default_sni_var.get().strip()
        max_cidr = self.cidr_limit_var.get()
        
        raw_ports = self.ports_var.get().split(',')
        ports =[int(p.strip()) for p in raw_ports if p.strip().isdigit() and 0 < int(p.strip()) <= 65535]
        if not ports: ports = [443]

        tasks = []
        for line in raw_lines:
            line = re.sub(r'^[۰-۹0-9]+\.\s*', '', line.strip())
            line = re.sub(r'^https?://', '', line, flags=re.IGNORECASE)
            line = line.split('/')[0] if '/' in line and not ('/' in line and any(c.isdigit() for c in line.split('/')[-1])) else line
            
            if not line: continue

            # تشخیص CIDR
            try:
                if '/' in line:
                    net = ipaddress.ip_network(line, strict=False)
                    hosts = list(net.hosts())[:max_cidr]
                    for h in hosts:
                        for p in ports: tasks.append((line, str(h), default_sni, p))
                    continue
            except ValueError:
                pass

            # تشخیص IP تنها
            try:
                ipaddress.ip_address(line)
                for p in ports: tasks.append((line, line, default_sni, p))
                continue
            except ValueError:
                pass

            # دامین
            for p in ports: tasks.append((line, line, line, p))

        if not tasks:
            messagebox.showwarning("خطا", "تارگت معتبری وارد نشده است.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.stat_total = len(tasks)
        self.stat_checked = 0
        self.stat_success = 0
        self.stat_ping_only = 0
        self.stat_down = 0
        self.update_metrics_ui()

        self.is_scanning = True
        self.stop_event.clear()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self.btn_export_csv.configure(state="disabled")
        self.lbl_status.configure(text=f"در حال اسکن {len(tasks)} هدف در شبکه...")

        threads = max(1, self.threads_var.get())
        self.executor = ThreadPoolExecutor(max_workers=threads)
        
        def background_submit():
            for task in tasks:
                if self.stop_event.is_set(): break
                self.executor.submit(self.scan_worker, task)
            self.executor.shutdown(wait=True)
            self.is_scanning = False
            self.root.after(0, self.finish_scan)

        threading.Thread(target=background_submit, daemon=True).start()

    def process_queue(self):
        while not self.result_queue.empty():
            res = self.result_queue.get()
            self.stat_checked += 1
            
            if res['cat'] == 'success': self.stat_success += 1
            elif res['cat'] == 'ping_only': self.stat_ping_only += 1
            else: self.stat_down += 1
            
            self.update_metrics_ui()
            
            tag = res['cat']
            # ستون‌های مخفی را با ویژگی tags ذخیره می‌کنیم تا موقع اکسپورت از sni_used استفاده کنیم
            item_id = self.tree.insert("", tk.END, values=(
                "☐", res['target'], res['ip'], res['port'], res['ping'], 
                res['sni'], res['cdn'], res['speed'], res['status']
            ), tags=(tag,))
            
            # ذخیره sni_used در دیکشنری پنهان treeview
            self.tree.item(item_id, text=res.get('sni_used', res['target']))
            
        self.tree.tag_configure("success", foreground="#198754")
        self.tree.tag_configure("ping_only", foreground="#0d6efd")
        self.tree.tag_configure("down", foreground="#dc3545")
        
        self.root.after(100, self.process_queue)

    def stop_scan(self):
        self.stop_event.set()
        self.lbl_status.configure(text="در حال لغو عملیات...")

    def finish_scan(self):
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_export.configure(state="normal")
        self.btn_export_csv.configure(state="normal")
        
        if self.stop_event.is_set():
            self.lbl_status.configure(text="عملیات توسط کاربر متوقف شد.")
        else:
            self.lbl_status.configure(text="رادار با موفقیت به کار خود پایان داد.")
        
        if self.auto_save_var.get():
            self.sort_results()
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                if "✔" in vals[8]:
                    self._check_item(child)
                    self.export_config(auto=True)
                    break

    def sort_results(self):
        items =[]
        for k in self.tree.get_children(""):
            vals = self.tree.item(k, "values")
            # امتیازدهی: SNI Usable > TCP OK > Ping Only > Down
            status_score = 3 if "SNI Usable" in vals[8] else (2 if "TCP" in vals[8] else (1 if "Ping" in vals[8] else 0))
            ping_val = float(vals[4].split()[0]) if "ms" in vals[4] else 99999
            speed_val = float(vals[7].split()[0]) if "KB" in vals[7] else 0.0
            
            # Sort: Highest Status, then Lowest Ping, then Highest Speed
            items.append((status_score, -ping_val, speed_val, k))
            
        items.sort(reverse=True, key=lambda x: (x[0], x[1], x[2]))
        
        for index, (_, _, _, k) in enumerate(items):
            self.tree.move(k, '', index)
        
        self.lbl_status.configure(text="نتایج مرتب شدند (بهترین کیفیت در صدر جدول).")

    def export_config(self, auto=False):
        selected_item = None
        for child in self.tree.get_children():
            if self.tree.item(child, "values")[0] == "☑":
                selected_item = child
                break
                
        if not selected_item:
            if not auto: messagebox.showwarning("خطا", "هیچ موردی انتخاب نشده است (☑).")
            return

        vals = self.tree.item(selected_item, "values")
        if "✔" not in vals[8]:
            if not auto: messagebox.showwarning("خطا", "ردیف انتخابی، پورت باز یا اتصال معتبری ندارد.")
            return

        ip = vals[2]
        port = int(vals[3])
        # واکشی SNI واقعی استفاده شده برای این تست (از text آیتم)
        sni_used = self.tree.item(selected_item, "text")

        config_data = {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": ip,
            "CONNECT_PORT": port,
            "FAKE_SNI": sni_used
        }

        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            if not auto:
                messagebox.showinfo("موفقیت", "فایل config.json ساخته شد.\n\nمسیر: " + os.path.abspath("config.json"))
            else:
                self.lbl_status.configure(text="بهترین سرور انتخاب و config.json آپدیت شد.")
        except Exception as e:
            if not auto: messagebox.showerror("خطا", str(e))

    def export_csv(self):
        valid_items =[]
        for child in self.tree.get_children():
            vals = self.tree.item(child, "values")
            sni_used = self.tree.item(child, "text")
            if "✔" in vals[8] or "◐" in vals[8]:
                valid_items.append([vals[1], vals[2], vals[3], vals[4], sni_used, vals[6], vals[7], vals[8]])

        if not valid_items:
            messagebox.showwarning("خطا", "داده موفقی برای خروجی وجود ندارد.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Enterprise_Radar_Export.csv")
        if not path: return

        try:
            with open(path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Target", "IP", "Port", "Ping", "Used SNI", "CDN Provider", "Speed", "Verdict"])
                writer.writerows(valid_items)
            messagebox.showinfo("موفقیت", "فایل CSV با موفقیت ذخیره شد.")
        except Exception as e:
            messagebox.showerror("خطا", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = SNIScannerApp(root)
    root.mainloop()
