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
import webbrowser
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ====== تنظیمات پایه و دیتابیس ======
VERSION = "v1.3.0"
GITHUB_API_URL = "https://api.github.com/repos/10ium/SNIScanner/releases/latest"
SETTINGS_FILE = "radar_settings.json"

CDN_PREFIXES = {
    "Cloudflare":["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69."],
    "Vercel":["76.76.", "66.33.", "216.230.", "198.169."],
    "Fastly":["151.101.", "199.232.", "146.75."],
    "Akamai":["23.", "96.", "124.", "125.", "184.", "203.", "205.", "212."],
    "Google Cloud":["34.", "35.", "104.15.", "130.211."],
    "AWS":["18.", "52.", "54.", "3.", "13."]
}

FALLBACK_DNS = {
    "cloudflare.com":["104.16.132.229", "104.16.133.229"],
    "vercel.com":["76.76.21.21", "198.169.2.193"],
    "nextjs.org":["216.230.86.65"],
    "npmjs.com":["104.17.134.117"],
    "react.dev":["66.33.60.193"],
}

DEFAULT_PORTS = "80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443"
DEFAULT_SPEED_URL = "/" # فایل پیش‌فرض برای تست سرعت (روت سرور)

# ====== سیستم زبان (i18n) ======
LANG = {
    "fa": {
        "title": f"رادار پیشرفته اس‌ان‌آی - {VERSION}",
        "telegram": "کانال تلگرام",
        "update": "بررسی بروزرسانی",
        "lang_toggle": "English",
        "theme_0": "☀️ روشن", "theme_1": "🌙 تاریک", "theme_2": "🌑 سیاه مطلق",
        "input_label": "ورودی (دامنه‌، آی‌پی، CIDR):",
        "paste": "📋 پیست", "browse": "📁 انتخاب فایل", "clear": "🗑 پاک کردن", "dedup": "✨ حذف تکراری‌ها",
        "settings": "تنظیمات رادار شبکه",
        "default_sni": ":SNI پیش‌فرض (برای آی‌پی)",
        "target_ports": ":پورت‌های هدف (خط جدید یا کاما)",
        "speed_url": ":مسیر تست سرعت (مثال: /10MB.bin)",
        "max_cidr": ":حداکثر بسط رنج (CIDR)",
        "threads": ":سرعت اسکن (موازی)",
        "timeout": ":زمان انتظار (ثانیه)",
        "rm_http": "حذف خودکار http:// از ورودی",
        "rm_www": "حذف خودکار .www از ورودی",
        "smart_ip": "فیلتر آی‌پی‌های داخلی و نامعتبر",
        "strict_ping": "حالت سخت‌گیرانه (الزام دریافت پینگ سالم)",
        "auto_scroll": "اسکرول خودکار جدول هنگام اسکن",
        "auto_save": "ساخت خودکار config.json پس از اتمام",
        "btn_save": "💾 ذخیره تنظیمات", "btn_stop": "توقف", "btn_start": "🚀 شروع رادار",
        "stat_scans": "تست‌های انجام شده", "stat_success": "موفق (متصل)", "stat_ping": "فقط پینگ", "stat_down": "مسدود / خطا",
        "btn_export_json": "ساخت config.json", "btn_export_csv": "خروجی گروهی (CSV)", "btn_export_custom": "⚙ خروجی سفارشی",
        "lbl_sort": "برای مرتب‌سازی روی عنوان ستون‌ها کلیک کنید",
        "col_select": "تیک", "col_target": "تارگت", "col_ip": "آی‌پی", "col_port": "پورت", "col_ping": "پینگ", "col_sni": "هندشیک", "col_cdn": "تأمین‌کننده", "col_speed": "سرعت", "col_status": "نتیجه نهایی",
        "ready": "رادار آماده اسکن شبکه است...",
        "msg_error": "خطا", "msg_success": "موفقیت", "msg_no_target": "تارگت معتبری وارد نشده است.",
        "msg_copied": "در کلیپ‌بورد کپی شد.", "msg_empty_clipboard": "کلیپ‌بورد خالی است.",
        "st_sni_usable": "✔ اس‌ان‌آی متصل", "st_tcp_ok": "✔ پورت باز", "st_ping_only": "◐ فقط پینگ", "st_down": "✖ مسدود", "st_timeout": "تایم‌اوت", "st_filtered": "✖ فیلتر شده",
        "st_valid": "معتبر", "st_invalid": "ناموفق",
        "targets_count": "تارگت‌های یکتا:",
        "time_elapsed": "سپری شده:", "time_eta": "باقی‌مانده:"
    },
    "en": {
        "title": f"Advanced SNI Radar - {VERSION}",
        "telegram": "Telegram Channel",
        "update": "Check for Updates",
        "lang_toggle": "فارسی",
        "theme_0": "☀️ Light", "theme_1": "🌙 Dark", "theme_2": "🌑 Pitch Black",
        "input_label": "Input (Domains, IPs, CIDRs):",
        "paste": "📋 Paste", "browse": "📁 Browse File", "clear": "🗑 Clear", "dedup": "✨ Remove Dupes",
        "settings": "Network Radar Settings",
        "default_sni": "Default SNI (for IPs):",
        "target_ports": "Target Ports (Comma/Newline):",
        "speed_url": "Speed Test Path (e.g. /10MB.bin):",
        "max_cidr": "Max CIDR Expand:",
        "threads": "Scan Speed (Threads):",
        "timeout": "Timeout (Seconds):",
        "rm_http": "Auto remove http:// from input",
        "rm_www": "Auto remove .www from input",
        "smart_ip": "Filter Private/Invalid IPs",
        "strict_ping": "Strict Mode (Require successful Ping)",
        "auto_scroll": "Auto-scroll table during scan",
        "auto_save": "Auto-create config.json on finish",
        "btn_save": "💾 Save Settings", "btn_stop": "Stop", "btn_start": "🚀 Start Radar",
        "stat_scans": "Scans Performed", "stat_success": "Success (Connected)", "stat_ping": "Ping Only", "stat_down": "Blocked / Error",
        "btn_export_json": "Create config.json", "btn_export_csv": "Export All (CSV)", "btn_export_custom": "⚙ Custom Export",
        "lbl_sort": "Click on column headers to sort results",
        "col_select": "Sel", "col_target": "Target", "col_ip": "IP Address", "col_port": "Port", "col_ping": "Ping", "col_sni": "Handshake", "col_cdn": "Provider", "col_speed": "Speed", "col_status": "Final Verdict",
        "ready": "Radar is ready to scan the network...",
        "msg_error": "Error", "msg_success": "Success", "msg_no_target": "No valid targets entered.",
        "msg_copied": "Copied to clipboard.", "msg_empty_clipboard": "Clipboard is empty.",
        "st_sni_usable": "✔ SNI Usable", "st_tcp_ok": "✔ Port Open", "st_ping_only": "◐ Ping Only", "st_down": "✖ Blocked", "st_timeout": "Timeout", "st_filtered": "✖ Filtered",
        "st_valid": "Valid", "st_invalid": "Failed",
        "targets_count": "Unique Targets:",
        "time_elapsed": "Elapsed:", "time_eta": "ETA:"
    }
}

class SNIScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1280x880")
        
        self.current_lang = "fa"
        self.theme_state = 0 # 0: Light, 1: Dark, 2: Pitch Black
        
        self.font_main = ("Tahoma", 9)
        self.font_bold = ("Tahoma", 9, "bold")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.is_scanning = False
        self.executor = None
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Stats & Time tracking
        self.stat_total_scans = 0
        self.stat_checked = 0
        self.stat_success = 0
        self.stat_ping_only = 0
        self.stat_down = 0
        self.stat_unique_targets = 0
        
        self.start_time = 0
        
        self.setup_ui()
        self.load_settings()
        self.apply_theme()
        self.apply_language()
        self.root.after(100, self.process_queue)
        self.root.after(1000, self.update_timer)

    def setup_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        # ====== پنل راست ======
        self.right_panel = ttk.Frame(self.root)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.right_panel.columnconfigure(0, weight=1)

        # Header Right
        header_frame = ttk.Frame(self.right_panel)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header_frame.columnconfigure(2, weight=1)
        
        self.btn_theme = ttk.Button(header_frame, command=self.cycle_theme, width=12)
        self.btn_theme.grid(row=0, column=0, sticky="w", padx=(0,2))

        self.btn_lang = ttk.Button(header_frame, command=self.toggle_language, width=8)
        self.btn_lang.grid(row=0, column=1, sticky="w", padx=2)
        
        self.lbl_update = tk.Label(header_frame, font=("Tahoma", 8, "underline"), fg="#198754", cursor="hand2")
        self.lbl_update.grid(row=0, column=2, sticky="w", padx=5)
        self.lbl_update.bind("<Button-1>", lambda e: self.check_for_updates())

        self.lbl_tg = tk.Label(header_frame, font=("Tahoma", 8, "underline"), fg="#0d6efd", cursor="hand2")
        self.lbl_tg.grid(row=0, column=3, sticky="e", padx=5)
        self.lbl_tg.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/vpnclashfa"))
        
        self.lbl_input_title = ttk.Label(header_frame, font=self.font_bold)
        self.lbl_input_title.grid(row=0, column=4, sticky="e")

        # Input Tools
        input_tools = ttk.Frame(self.right_panel)
        input_tools.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        
        self.btn_paste = ttk.Button(input_tools, command=self.paste_from_clipboard)
        self.btn_paste.pack(side="left", padx=2)
        
        self.btn_browse = ttk.Button(input_tools, command=self.load_from_file)
        self.btn_browse.pack(side="left", padx=2)
        
        self.btn_dedup = ttk.Button(input_tools, command=self.remove_duplicates)
        self.btn_dedup.pack(side="left", padx=2)

        self.btn_clear = ttk.Button(input_tools, command=lambda: self.text_input.delete("1.0", tk.END))
        self.btn_clear.pack(side="right", padx=2)

        self.text_input = tk.Text(self.right_panel, width=40, height=10, font=("Consolas", 10))
        self.text_input.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        self.right_panel.rowconfigure(2, weight=1)

        # ====== پنل تنظیمات ======
        self.settings_frame = ttk.LabelFrame(self.right_panel, padding=10)
        self.settings_frame.grid(row=3, column=0, sticky="nsew")
        self.settings_frame.columnconfigure(1, weight=1)

        row_idx = 0
        self.default_sni_var = tk.StringVar(value="yahoo.com")
        ttk.Entry(self.settings_frame, textvariable=self.default_sni_var, justify="left").grid(row=row_idx, column=0, sticky="ew", padx=5, pady=5)
        self.lbl_set_sni = ttk.Label(self.settings_frame)
        self.lbl_set_sni.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)
        
        row_idx += 1
        ports_frame = ttk.Frame(self.settings_frame)
        ports_frame.grid(row=row_idx, column=0, sticky="ew", padx=5, pady=5)
        self.ports_input = tk.Text(ports_frame, height=2, width=25, font=("Consolas", 10))
        self.ports_input.insert("1.0", DEFAULT_PORTS)
        self.ports_input.pack(side="left", fill="x", expand=True)
        self.lbl_set_ports = ttk.Label(self.settings_frame)
        self.lbl_set_ports.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        # فیلد جدید: تست سرعت شخصی‌سازی شده
        row_idx += 1
        self.speed_url_var = tk.StringVar(value=DEFAULT_SPEED_URL)
        ttk.Entry(self.settings_frame, textvariable=self.speed_url_var, justify="left").grid(row=row_idx, column=0, sticky="ew", padx=5, pady=5)
        self.lbl_set_speed_url = ttk.Label(self.settings_frame)
        self.lbl_set_speed_url.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.cidr_limit_var = tk.IntVar(value=256)
        ttk.Entry(self.settings_frame, textvariable=self.cidr_limit_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_cidr = ttk.Label(self.settings_frame)
        self.lbl_set_cidr.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.threads_var = tk.IntVar(value=20)
        ttk.Entry(self.settings_frame, textvariable=self.threads_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_threads = ttk.Label(self.settings_frame)
        self.lbl_set_threads.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Entry(self.settings_frame, textvariable=self.timeout_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_timeout = ttk.Label(self.settings_frame)
        self.lbl_set_timeout.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.remove_http_var = tk.BooleanVar(value=True)
        self.chk_rm_http = ttk.Checkbutton(self.settings_frame, variable=self.remove_http_var)
        self.chk_rm_http.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.remove_www_var = tk.BooleanVar(value=True)
        self.chk_rm_www = ttk.Checkbutton(self.settings_frame, variable=self.remove_www_var)
        self.chk_rm_www.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.smart_ip_var = tk.BooleanVar(value=True)
        self.chk_smart_ip = ttk.Checkbutton(self.settings_frame, variable=self.smart_ip_var)
        self.chk_smart_ip.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.strict_ping_var = tk.BooleanVar(value=False)
        self.chk_strict_ping = ttk.Checkbutton(self.settings_frame, variable=self.strict_ping_var)
        self.chk_strict_ping.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self.chk_auto_scroll = ttk.Checkbutton(self.settings_frame, variable=self.auto_scroll_var)
        self.chk_auto_scroll.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_save_var = tk.BooleanVar(value=True)
        self.chk_auto_save = ttk.Checkbutton(self.settings_frame, variable=self.auto_save_var)
        self.chk_auto_save.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        # دکمه‌های کنترل
        btn_frame = ttk.Frame(self.right_panel)
        btn_frame.grid(row=4, column=0, sticky="nsew", pady=10)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        self.btn_save_settings = ttk.Button(btn_frame, command=self.save_settings)
        self.btn_save_settings.grid(row=0, column=0, sticky="nsew", padx=2)

        self.btn_stop = ttk.Button(btn_frame, command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=1, sticky="nsew", padx=2)

        self.btn_start = ttk.Button(btn_frame, style="Primary.TButton", command=self.start_scan)
        self.btn_start.grid(row=0, column=2, sticky="nsew", padx=2)

        # ====== پنل چپ ======
        self.left_panel = ttk.Frame(self.root)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.left_panel.columnconfigure(0, weight=1)
        self.left_panel.rowconfigure(3, weight=1)

        # 1. داشبورد آمار زنده
        self.dash_frame = tk.Frame(self.left_panel)
        self.dash_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        self.stat_frames = []
        self.lbl_stat_total_val, self.lbl_stat_total_title = self.create_metric_card(self.dash_frame, "#e9ecef", "#495057")
        self.lbl_stat_success_val, self.lbl_stat_success_title = self.create_metric_card(self.dash_frame, "#d1e7dd", "#0f5132")
        self.lbl_stat_ping_val, self.lbl_stat_ping_title = self.create_metric_card(self.dash_frame, "#cff4fc", "#055160")
        self.lbl_stat_down_val, self.lbl_stat_down_title = self.create_metric_card(self.dash_frame, "#f8d7da", "#842029")

        # 2. نوار پیشرفت و زمان‌سنج (Progress Dashboard)
        progress_frame = ttk.Frame(self.left_panel)
        progress_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        progress_frame.columnconfigure(1, weight=1)

        self.lbl_progress_pct = ttk.Label(progress_frame, text="0%", font=self.font_bold, width=5)
        self.lbl_progress_pct.grid(row=0, column=0, sticky="w", padx=(0,5))

        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=5)

        self.lbl_time_info = ttk.Label(progress_frame, text="", font=("Consolas", 8))
        self.lbl_time_info.grid(row=0, column=2, sticky="e", padx=(5,0))

        # 3. ابزارهای بالای جدول
        tools_frame = ttk.Frame(self.left_panel)
        tools_frame.grid(row=2, column=0, sticky="ew", pady=(0, 5))
        
        self.btn_export_json = ttk.Button(tools_frame, style="Success.TButton", command=self.export_config)
        self.btn_export_json.pack(side="left", padx=2)
        
        self.btn_export_csv = ttk.Button(tools_frame, command=self.export_csv)
        self.btn_export_csv.pack(side="left", padx=2)

        self.btn_export_custom = ttk.Button(tools_frame, command=self.open_custom_export_dialog)
        self.btn_export_custom.pack(side="left", padx=2)
        
        self.lbl_targets_count = ttk.Label(tools_frame, font=self.font_bold, foreground="#198754")
        self.lbl_targets_count.pack(side="left", padx=15)

        # دکمه‌های اسکرول سریع
        btn_scroll_down = ttk.Button(tools_frame, text="⬇️", width=3, command=lambda: self.tree.yview_moveto(1))
        btn_scroll_down.pack(side="right", padx=2)
        btn_scroll_up = ttk.Button(tools_frame, text="⬆️", width=3, command=lambda: self.tree.yview_moveto(0))
        btn_scroll_up.pack(side="right", padx=2)

        self.lbl_sort_guide = ttk.Label(tools_frame, font=("Tahoma", 8))
        self.lbl_sort_guide.pack(side="right", padx=10)

        # 4. جدول نتایج
        columns = ("select", "target", "ip", "port", "ping", "sni", "cdn", "speed", "status")
        self.tree = ttk.Treeview(self.left_panel, columns=columns, show="headings")
        
        self.tree.column("select", width=40, anchor="center")
        self.tree.column("target", width=120, anchor="w")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("port", width=50, anchor="center")
        self.tree.column("ping", width=75, anchor="center")
        self.tree.column("sni", width=80, anchor="center")
        self.tree.column("cdn", width=100, anchor="center")
        self.tree.column("speed", width=80, anchor="center")
        self.tree.column("status", width=110, anchor="center")

        self.tree.grid(row=3, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(self.left_panel, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=3, column=1, sticky='ns')

        self.tree.bind('<ButtonRelease-1>', self.toggle_check)

        self.lbl_status = ttk.Label(self.left_panel)
        self.lbl_status.grid(row=4, column=0, sticky="e", pady=5)

    def create_metric_card(self, parent, bg_color, fg_color):
        frame = tk.Frame(parent, bg=bg_color, bd=1, relief="ridge")
        frame.pack(side="left", fill="both", expand=True, padx=3)
        self.stat_frames.append(frame)
        lbl_val = tk.Label(frame, text="0", font=("Consolas", 15, "bold"), bg=bg_color, fg=fg_color)
        lbl_val.pack(pady=(8,0))
        lbl_title = tk.Label(frame, font=("Tahoma", 8, "bold"), bg=bg_color, fg=fg_color)
        lbl_title.pack(pady=(0,8))
        return lbl_val, lbl_title

    def apply_language(self):
        t = LANG[self.current_lang]
        self.root.title(t["title"])
        self.lbl_tg.configure(text=t["telegram"])
        self.lbl_update.configure(text=t["update"])
        self.btn_lang.configure(text=t["lang_toggle"])
        self.btn_theme.configure(text=t[f"theme_{self.theme_state}"])
        self.lbl_input_title.configure(text=t["input_label"])
        
        self.btn_paste.configure(text=t["paste"])
        self.btn_browse.configure(text=t["browse"])
        self.btn_clear.configure(text=t["clear"])
        self.btn_dedup.configure(text=t["dedup"])
        
        self.settings_frame.configure(text=f" {t['settings']} ")
        self.lbl_set_sni.configure(text=t["default_sni"])
        self.lbl_set_ports.configure(text=t["target_ports"])
        self.lbl_set_speed_url.configure(text=t["speed_url"])
        self.lbl_set_cidr.configure(text=t["max_cidr"])
        self.lbl_set_threads.configure(text=t["threads"])
        self.lbl_set_timeout.configure(text=t["timeout"])
        
        self.chk_rm_http.configure(text=t["rm_http"])
        self.chk_rm_www.configure(text=t["rm_www"])
        self.chk_smart_ip.configure(text=t["smart_ip"])
        self.chk_strict_ping.configure(text=t["strict_ping"])
        self.chk_auto_scroll.configure(text=t["auto_scroll"])
        self.chk_auto_save.configure(text=t["auto_save"])
        
        self.btn_save_settings.configure(text=t["btn_save"])
        self.btn_stop.configure(text=t["btn_stop"])
        self.btn_start.configure(text=t["btn_start"])
        
        self.lbl_stat_total_title.configure(text=t["stat_scans"])
        self.lbl_stat_success_title.configure(text=t["stat_success"])
        self.lbl_stat_ping_title.configure(text=t["stat_ping"])
        self.lbl_stat_down_title.configure(text=t["stat_down"])
        
        self.btn_export_json.configure(text=t["btn_export_json"])
        self.btn_export_csv.configure(text=t["btn_export_csv"])
        self.btn_export_custom.configure(text=t["btn_export_custom"])
        self.lbl_sort_guide.configure(text=t["lbl_sort"])
        self.lbl_targets_count.configure(text=f"{t['targets_count']} {self.stat_unique_targets}")
        
        if not self.is_scanning:
            self.lbl_status.configure(text=t["ready"])
            self.lbl_time_info.configure(text=f"{t['time_elapsed']} 00:00 | {t['time_eta']} --:--")

        for col, key in [("select","col_select"), ("target","col_target"), ("ip","col_ip"), ("port","col_port"), 
                         ("ping","col_ping"), ("sni","col_sni"), ("cdn","col_cdn"), ("speed","col_speed"), ("status","col_status")]:
            self.tree.heading(col, text=t[key], command=lambda c=col: self.treeview_sort_column(c, False))

    def toggle_language(self):
        self.current_lang = "en" if self.current_lang == "fa" else "fa"
        self.apply_language()

    def cycle_theme(self):
        self.theme_state = (self.theme_state + 1) % 3
        self.apply_theme()
        self.apply_language()

    def apply_theme(self):
        self.style.configure("Primary.TButton", font=self.font_bold, background="#0d6efd", foreground="white", padding=6)
        self.style.map("Primary.TButton", background=[("active", "#0b5ed7")])

        if self.theme_state == 0: 
            bg_color = "#f8f9fa"
            fg_color = "#212529"
            tree_bg = "white"
            tree_fg = "#212529"
            input_bg = "white"
            dash_bgs = ["#e9ecef", "#d1e7dd", "#cff4fc", "#f8d7da"]
            dash_fgs = ["#495057", "#0f5132", "#055160", "#842029"]
        elif self.theme_state == 1: 
            bg_color = "#212529"
            fg_color = "#f8f9fa"
            tree_bg = "#343a40"
            tree_fg = "#f8f9fa"
            input_bg = "#495057"
            dash_bgs = ["#343a40", "#198754", "#0dcaf0", "#dc3545"]
            dash_fgs = ["#f8f9fa", "#fff", "#000", "#fff"]
        else: 
            bg_color = "#000000"
            fg_color = "#a0a0a0"
            tree_bg = "#050505"
            tree_fg = "#b0b0b0"
            input_bg = "#111111"
            dash_bgs = ["#111111", "#051f0f", "#001a22", "#2b0a0a"]
            dash_fgs = ["#a0a0a0", "#34d399", "#38bdf8", "#f87171"]

        self.root.configure(bg=bg_color)
        self.dash_frame.configure(bg=bg_color)
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        
        self.style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg)
        self.style.map('Treeview', background=[('selected', '#2a2a2a' if self.theme_state==2 else '#0078D7')])
        
        self.text_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)
        self.ports_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)

        for i, frame in enumerate(self.stat_frames):
            frame.configure(bg=dash_bgs[i])
            for widget in frame.winfo_children():
                widget.configure(bg=dash_bgs[i], fg=dash_fgs[i])

    def format_time(self, seconds):
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h > 0: return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def update_timer(self):
        if self.is_scanning:
            elapsed = time.time() - self.start_time
            
            eta = 0
            if self.stat_checked > 0:
                speed = self.stat_checked / elapsed
                remaining_tasks = self.stat_total_scans - self.stat_checked
                eta = remaining_tasks / speed if speed > 0 else 0

            t = LANG[self.current_lang]
            self.lbl_time_info.configure(text=f"{t['time_elapsed']} {self.format_time(elapsed)} | {t['time_eta']} {self.format_time(eta)}")
            
        self.root.after(1000, self.update_timer)

    def update_metrics_ui(self):
        self.lbl_stat_total_val.configure(text=f"{self.stat_checked} / {self.stat_total_scans}")
        self.lbl_stat_success_val.configure(text=str(self.stat_success))
        self.lbl_stat_ping_val.configure(text=str(self.stat_ping_only))
        self.lbl_stat_down_val.configure(text=str(self.stat_down))
        
        if self.stat_total_scans > 0:
            pct = (self.stat_checked / self.stat_total_scans) * 100
            self.progress_bar["value"] = pct
            self.lbl_progress_pct.configure(text=f"{int(pct)}%")

    def check_for_updates(self):
        try:
            req = urllib.request.Request(GITHUB_API_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                latest_version = data.get("tag_name", VERSION)
                if latest_version != VERSION:
                    msg = f"نسخه جدید ({latest_version}) منتشر شده است.\nآیا می‌خواهید به صفحه دانلود بروید؟" if self.current_lang=="fa" else f"New version ({latest_version}) is available.\nDo you want to open the download page?"
                    if messagebox.askyesno("Update Available", msg):
                        webbrowser.open(data.get("html_url", ""))
                else:
                    msg = "شما از آخرین نسخه استفاده می‌کنید." if self.current_lang=="fa" else "You are using the latest version."
                    messagebox.showinfo("Up to date", msg)
        except Exception as e:
            msg = "هیچ نسخه‌ای روی مخزن گیت‌هاب یافت نشد." if self.current_lang=="fa" else "No releases found on GitHub repository."
            messagebox.showinfo("Info", msg)

    def save_settings(self):
        settings = {
            "targets": self.text_input.get("1.0", tk.END).strip(),
            "ports": self.ports_input.get("1.0", tk.END).strip(),
            "default_sni": self.default_sni_var.get(),
            "speed_url": self.speed_url_var.get(),
            "cidr_limit": self.cidr_limit_var.get(),
            "threads": self.threads_var.get(),
            "timeout": self.timeout_var.get(),
            "remove_http": self.remove_http_var.get(),
            "remove_www": self.remove_www_var.get(),
            "smart_ip": self.smart_ip_var.get(),
            "strict_ping": self.strict_ping_var.get(),
            "auto_scroll": self.auto_scroll_var.get(),
            "auto_save": self.auto_save_var.get(),
            "theme_state": self.theme_state,
            "lang": self.current_lang
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=4)
            messagebox.showinfo(LANG[self.current_lang]["msg_success"], "Settings saved.")
        except Exception as e:
            messagebox.showerror(LANG[self.current_lang]["msg_error"], str(e))

    def load_settings(self):
        if not os.path.exists(SETTINGS_FILE): return
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                settings = json.load(f)
            
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", settings.get("targets", ""))
            
            self.ports_input.delete("1.0", tk.END)
            self.ports_input.insert("1.0", settings.get("ports", DEFAULT_PORTS))
            
            self.default_sni_var.set(settings.get("default_sni", "yahoo.com"))
            self.speed_url_var.set(settings.get("speed_url", DEFAULT_SPEED_URL))
            self.cidr_limit_var.set(settings.get("cidr_limit", 256))
            self.threads_var.set(settings.get("threads", 20))
            self.timeout_var.set(settings.get("timeout", 2.0))
            self.remove_http_var.set(settings.get("remove_http", True))
            self.remove_www_var.set(settings.get("remove_www", True))
            self.smart_ip_var.set(settings.get("smart_ip", True))
            self.strict_ping_var.set(settings.get("strict_ping", False))
            self.auto_scroll_var.set(settings.get("auto_scroll", True))
            self.auto_save_var.set(settings.get("auto_save", True))
            
            self.theme_state = settings.get("theme_state", 0)
            self.current_lang = settings.get("lang", "fa")
        except Exception:
            pass

    def paste_from_clipboard(self):
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                self.text_input.insert(tk.END, clipboard_text + "\n")
        except tk.TclError:
            messagebox.showwarning(LANG[self.current_lang]["msg_error"], LANG[self.current_lang]["msg_empty_clipboard"])

    def load_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.text_input.insert(tk.END, f.read() + "\n")
            except Exception as e:
                messagebox.showerror(LANG[self.current_lang]["msg_error"], str(e))

    def remove_duplicates(self):
        lines = self.text_input.get("1.0", tk.END).split('\n')
        unique = list(dict.fromkeys(l.strip() for l in lines if l.strip()))
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", '\n'.join(unique) + '\n')

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

    def treeview_sort_column(self, col, reverse):
        l =[(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        if col in ("ping", "speed", "port"):
            def extract_number(val):
                nums = re.findall(r'\d+\.?\d*', str(val))
                return float(nums[0]) if nums else (999999.0 if col=="ping" else 0.0)
            l.sort(key=lambda t: extract_number(t[0]), reverse=reverse)
        else:
            l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.treeview_sort_column(col, not reverse))

    def sort_results_by_default(self):
        items =[]
        for k in self.tree.get_children(""):
            vals = self.tree.item(k, "values")
            st_text = vals[8]
            t = LANG[self.current_lang]
            score = 3 if t["st_sni_usable"] in st_text else (2 if t["st_tcp_ok"] in st_text else (1 if t["st_ping_only"] in st_text else 0))
            ping_val = float(vals[4].split()[0]) if "ms" in vals[4] else 999999.0
            speed_val = float(vals[7].split()[0]) if "KB" in vals[7] else 0.0
            items.append((score, -ping_val, speed_val, k))
            
        items.sort(reverse=True, key=lambda x: (x[0], x[1], x[2]))
        for index, (_, _, _, k) in enumerate(items):
            self.tree.move(k, '', index)

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
        return "Unknown" if self.current_lang=="en" else "نامشخص"

    def icmp_ping(self, ip, timeout):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        t_param = '-w' if platform.system().lower() == 'windows' else '-W'
        t_val = str(int(timeout * 1000)) if platform.system().lower() == 'windows' else str(max(1, int(timeout)))
        cmd =['ping', param, '1', t_param, t_val, ip]
        
        kwargs = {}
        if platform.system().lower() == 'windows':
            kwargs['creationflags'] = 0x08000000 
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1, **kwargs)
            if res.returncode == 0:
                match = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)', res.stdout, re.IGNORECASE)
                if match: return True, float(match.group(1))
                return True, 1.0
        except Exception:
            pass
        return False, None

    def measure_speed(self, ip, port, sni, timeout):
        req_path = self.speed_url_var.get().strip()
        if not req_path.startswith('/'): req_path = '/' + req_path

        try:
            start = time.time()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                if port in[443, 8443, 2053, 2083, 2087, 2096]:
                    with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                        req = f"GET {req_path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(req.encode())
                        bytes_recv = 0
                        while True:
                            data = ssock.recv(4096)
                            if not data: break
                            bytes_recv += len(data)
                            if time.time() - start > 1.0: break
                else:
                    req = f"GET {req_path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
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

    def clean_target(self, target):
        t = target.strip()
        t = re.sub(r'^[۰-۹0-9]+\.\s*', '', t) 
        if self.remove_http_var.get():
            t = re.sub(r'^https?://', '', t, flags=re.IGNORECASE)
        if self.remove_www_var.get():
            t = re.sub(r'^www\.', '', t, flags=re.IGNORECASE)
        t = t.split('/')[0] if '/' in t and not ('/' in t and any(c.isdigit() for c in t.split('/')[-1])) else t
        return t.strip()

    def scan_worker(self, task):
        if self.stop_event.is_set(): return
        
        target_label, test_host, sni_to_use, port = task
        timeout_val = self.timeout_var.get()
        strict_ping = self.strict_ping_var.get()
        t = LANG[self.current_lang]

        ips_to_test =[]
        try:
            ipaddress.ip_address(test_host)
            ips_to_test = [test_host]
        except ValueError:
            try:
                _, _, resolved = socket.gethostbyname_ex(test_host)
                ips_to_test.extend(resolved)
            except Exception:
                if test_host in FALLBACK_DNS:
                    ips_to_test.extend(FALLBACK_DNS[test_host])

        valid_ips = list(set([ip for ip in ips_to_test if self.is_valid_ip(ip)]))
        
        if not valid_ips:
            self.result_queue.put({
                'target': target_label, 'ip': '-', 'port': port, 'ping': '-', 
                'sni': '-', 'cdn': '-', 'speed': '-', 'status': 'DNS Error', 'cat': 'down'
            })
            return

        for ip in valid_ips:
            if self.stop_event.is_set(): return
            
            cdn_name = self.detect_cdn(ip)
            ping_ok, ping_ms = self.icmp_ping(ip, timeout_val)
            
            if strict_ping and not ping_ok:
                self.result_queue.put({
                    'target': target_label, 'ip': ip, 'port': port, 'ping': t["st_timeout"], 
                    'sni': '-', 'cdn': cdn_name, 'speed': '-', 'status': t["st_filtered"], 'cat': 'down'
                })
                continue

            tcp_ok = False
            tls_ok = False
            try:
                with socket.create_connection((ip, port), timeout=timeout_val) as sock:
                    tcp_ok = True
                    if port in[443, 8443, 2053, 2083, 2087, 2096]:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with ctx.wrap_socket(sock, server_hostname=sni_to_use):
                            tls_ok = True
            except Exception:
                pass

            speed_kb = "-"
            status = ""
            cat = ""

            if tls_ok:
                speed_kb = f"{self.measure_speed(ip, port, sni_to_use, timeout_val)} KB/s"
                status = t["st_sni_usable"]
                cat = "success"
            elif tcp_ok:
                status = t["st_tcp_ok"]
                cat = "success"
            elif ping_ok:
                status = t["st_ping_only"]
                cat = "ping_only"
            else:
                status = t["st_down"]
                cat = "down"

            self.result_queue.put({
                'target': target_label, 'ip': ip, 'port': port, 
                'ping': f"{ping_ms} ms" if ping_ok else t["st_timeout"], 
                'sni': t["st_valid"] if tls_ok else (t["st_invalid"] if tcp_ok else '-'), 
                'cdn': cdn_name, 'speed': speed_kb, 'status': status, 'cat': cat, 'sni_used': sni_to_use
            })

    def start_scan(self):
        raw_lines = self.text_input.get("1.0", tk.END).strip().split('\n')
        default_sni = self.default_sni_var.get().strip()
        max_cidr = self.cidr_limit_var.get()
        
        raw_ports = self.ports_input.get("1.0", tk.END).replace('\n', ',').split(',')
        ports =[int(p.strip()) for p in raw_ports if p.strip().isdigit() and 0 < int(p.strip()) <= 65535]
        if not ports: ports = [443]

        unique_targets_set = set()
        tasks =[]
        
        for line in raw_lines:
            cleaned_line = self.clean_target(line)
            if not cleaned_line: continue
            
            unique_targets_set.add(cleaned_line)

            try:
                if '/' in cleaned_line:
                    net = ipaddress.ip_network(cleaned_line, strict=False)
                    hosts = list(net.hosts())[:max_cidr]
                    for h in hosts:
                        for p in ports: tasks.append((cleaned_line, str(h), default_sni, p))
                    continue
            except ValueError:
                pass

            try:
                ipaddress.ip_address(cleaned_line)
                for p in ports: tasks.append((cleaned_line, cleaned_line, default_sni, p))
                continue
            except ValueError:
                pass

            for p in ports: tasks.append((cleaned_line, cleaned_line, cleaned_line, p))

        if not tasks:
            messagebox.showwarning(LANG[self.current_lang]["msg_error"], LANG[self.current_lang]["msg_no_target"])
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.stat_unique_targets = len(unique_targets_set)
        self.stat_total_scans = len(tasks)
        self.stat_checked = 0
        self.stat_success = 0
        self.stat_ping_only = 0
        self.stat_down = 0
        self.progress_bar["value"] = 0
        self.lbl_progress_pct.configure(text="0%")
        
        self.lbl_targets_count.configure(text=f"{LANG[self.current_lang]['targets_count']} {self.stat_unique_targets}")
        self.update_metrics_ui()

        self.is_scanning = True
        self.start_time = time.time()
        self.stop_event.clear()
        
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export_json.configure(state="disabled")
        self.btn_export_csv.configure(state="disabled")
        self.btn_export_custom.configure(state="disabled")
        
        self.lbl_status.configure(text=f"Scanning {self.stat_total_scans} combinations...")

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
            item_id = self.tree.insert("", tk.END, values=(
                "☐", res['target'], res['ip'], res['port'], res['ping'], 
                res['sni'], res['cdn'], res['speed'], res['status']
            ), tags=(tag,))
            
            self.tree.item(item_id, text=res.get('sni_used', res['target']))
            
            if self.auto_scroll_var.get():
                self.tree.see(item_id)
            
        self.tree.tag_configure("success", foreground="#198754" if self.theme_state!=2 else "#34d399")
        self.tree.tag_configure("ping_only", foreground="#0d6efd" if self.theme_state!=2 else "#38bdf8")
        self.tree.tag_configure("down", foreground="#dc3545" if self.theme_state!=2 else "#f87171")
        
        self.root.after(100, self.process_queue)

    def stop_scan(self):
        self.stop_event.set()

    def finish_scan(self):
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_export_json.configure(state="normal")
        self.btn_export_csv.configure(state="normal")
        self.btn_export_custom.configure(state="normal")
        
        self.progress_bar["value"] = 100
        self.lbl_progress_pct.configure(text="100%")
        
        self.sort_results_by_default()
        self.lbl_status.configure(text="Finished.")
        
        if self.auto_save_var.get():
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                if "✔" in vals[8]:
                    self._check_item(child)
                    self.export_config(auto=True)
                    break

    def export_config(self, auto=False):
        selected_item = None
        for child in self.tree.get_children():
            if self.tree.item(child, "values")[0] == "☑":
                selected_item = child
                break
                
        if not selected_item:
            if not auto: messagebox.showwarning("Warning", "No item selected (☑).")
            return

        vals = self.tree.item(selected_item, "values")
        if "✔" not in vals[8]:
            if not auto: messagebox.showwarning("Warning", "Selected row does not have a valid connection.")
            return

        config_data = {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": vals[2],
            "CONNECT_PORT": int(vals[3]),
            "FAKE_SNI": self.tree.item(selected_item, "text")
        }

        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            if not auto: messagebox.showinfo("Success", "config.json created.")
        except Exception as e:
            if not auto: messagebox.showerror("Error", str(e))

    def export_csv(self):
        valid_items =[]
        for child in self.tree.get_children():
            vals = self.tree.item(child, "values")
            sni_used = self.tree.item(child, "text")
            if "✔" in vals[8] or "◐" in vals[8]:
                valid_items.append([vals[1], vals[2], vals[3], vals[4], sni_used, vals[6], vals[7], vals[8]])

        if not valid_items:
            messagebox.showwarning("Warning", "No successful data to export.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Radar_Export.csv")
        if not path: return

        try:
            with open(path, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                headers = [LANG[self.current_lang][k] for k in ["col_target", "col_ip", "col_port", "col_ping", "col_sni", "col_cdn", "col_speed", "col_status"]]
                writer.writerow(headers)
                writer.writerows(valid_items)
            messagebox.showinfo("Success", "CSV Saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_custom_export_dialog(self):
        top = tk.Toplevel(self.root)
        top.title(LANG[self.current_lang]["btn_export_custom"])
        top.geometry("400x260")
        top.transient(self.root)
        top.grab_set()
        
        bg_col = "#000" if self.theme_state==2 else ("#212529" if self.theme_state==1 else "#f8f9fa")
        fg_col = "#a0a0a0" if self.theme_state==2 else ("white" if self.theme_state==1 else "black")
        top.configure(bg=bg_col)

        t = LANG[self.current_lang]
        ttk.Label(top, text="Filter by Status:", background=bg_col, foreground=fg_col).pack(pady=(15, 5))
        status_var = tk.StringVar(value="All Success")
        status_combo = ttk.Combobox(top, textvariable=status_var, state="readonly", justify="center")
        status_combo['values'] = ("All Success", t["st_sni_usable"], t["st_tcp_ok"], t["st_ping_only"])
        status_combo.pack(fill="x", padx=40)

        ttk.Label(top, text="Filter by CDN:", background=bg_col, foreground=fg_col).pack(pady=(15, 5))
        cdn_var = tk.StringVar(value="All CDNs")
        cdn_combo = ttk.Combobox(top, textvariable=cdn_var, state="readonly", justify="center")
        cdn_combo['values'] = ("All CDNs", "Cloudflare", "Vercel", "Fastly", "Akamai", "Google Cloud", "AWS", "Unknown", "نامشخص")
        cdn_combo.pack(fill="x", padx=40)

        def perform_custom_export():
            st_filter = status_var.get()
            cdn_filter = cdn_var.get()
            valid_items =[]
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                sni_used = self.tree.item(child, "text")
                
                if st_filter == "All Success":
                    if "✖" in vals[8] or "Error" in vals[8] or "خطا" in vals[8]: continue
                else:
                    if st_filter not in vals[8]: continue
                
                if cdn_filter != "All CDNs":
                    if cdn_filter not in vals[6]: continue

                valid_items.append([vals[1], vals[2], vals[3], vals[4], sni_used, vals[6], vals[7], vals[8]])

            if not valid_items:
                messagebox.showwarning("Warning", "No results match these filters.", parent=top)
                return
            
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Custom_Export.csv", parent=top)
            if not path: return

            try:
                with open(path, mode='w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    headers = [t[k] for k in ["col_target", "col_ip", "col_port", "col_ping", "col_sni", "col_cdn", "col_speed", "col_status"]]
                    writer.writerow(headers)
                    writer.writerows(valid_items)
                messagebox.showinfo("Success", "Custom CSV Exported.", parent=top)
                top.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=top)

        btn_save = ttk.Button(top, text="Export", style="Primary.TButton", command=perform_custom_export)
        btn_save.pack(pady=25)

if __name__ == "__main__":
    root = tk.Tk()
    app = SNIScannerApp(root)
    root.mainloop()
