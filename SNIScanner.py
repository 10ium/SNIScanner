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
import statistics

# ====== تنظیمات پایه ======
VERSION = "v1.6.0"
GITHUB_API_URL = "https://api.github.com/repos/10ium/SNIScanner/releases/latest"
SETTINGS_FILE = "radar_settings.json"

# ====== دیتابیس دقیق شبکه‌ها ======
CDN_RANGES = [
    ("Cloudflare", ["1.0.0.0/24","1.1.1.0/24","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20","190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"]),
    ("Google Cloud", ["8.8.4.0/24","8.8.8.0/24","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","74.125.0.0/16","104.132.0.0/14","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","172.253.0.0/16","173.194.0.0/16","209.85.128.0/17","216.58.192.0/19","216.239.32.0/19"]),
    ("Fastly", ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","104.156.80.0/20","146.75.0.0/16","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","199.27.72.0/21","199.232.0.0/16"]),
    ("Akamai", ["2.16.0.0/13","23.0.0.0/12","23.32.0.0/11","23.64.0.0/14","23.72.0.0/13","23.192.0.0/11","63.0.0.0/8","69.192.0.0/16","72.246.0.0/15","88.221.0.0/16","95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.50.0.0/15","184.84.0.0/14"]),
    ("Netlify", ["3.33.128.0/17","13.32.0.0/15","13.35.0.0/16","18.64.0.0/14","44.226.105.0/24","50.7.4.0/24","50.7.85.0/24","50.7.87.0/24","44.235.184.0/24","52.84.0.0/15","35.157.26.0/24","63.176.8.0/24","54.182.0.0/16","99.83.128.0/17","162.159.128.0/20"]),
    ("Vercel", ["64.29.17.0/24","64.29.18.0/24","64.29.19.0/24","66.33.60.0/24","66.33.61.0/24","76.76.21.0/24","76.223.126.0/24"]),
    ("CloudFront", ["52.46.0.0/18","52.84.0.0/15","54.182.0.0/16","99.84.0.0/16","130.176.0.0/17"]),
    ("BunnyCDN", ["89.187.160.0/19","147.75.0.0/16"]),
    ("Gcore", ["92.223.0.0/16","95.85.0.0/16","185.158.0.0/16"]),
    ("ArvanCloud", ["185.220.226.0/24","185.143.232.0/22"]),
]

COMPILED_SUBNETS = []
for cdn_name, subnets in CDN_RANGES:
    for sub in subnets:
        try:
            COMPILED_SUBNETS.append((ipaddress.ip_network(sub, strict=False), cdn_name))
        except ValueError:
            pass

FALLBACK_DNS = {
    "cloudflare.com":["104.16.132.229", "104.16.133.229"],
    "vercel.com":["76.76.21.21", "198.169.2.193"],
    "nextjs.org":["216.230.86.65"],
    "npmjs.com":["104.17.134.117"],
    "react.dev":["66.33.60.193"],
}

DEFAULT_PORTS = "80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443"
DEFAULT_SPEED_URL = "/"

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
        "target_ports": ":پورت‌های هدف (خط جدید یا کاما/خط فاصله برای رنج)",
        "speed_url": ":مسیر تست سرعت (مثال: /10MB.bin)",
        "max_cidr": ":حداکثر بسط رنج (CIDR)",
        "threads": ":سرعت اسکن (موازی)",
        "timeout": ":زمان انتظار (ثانیه)",
        "retry_count": ":تعداد تلاش مجدد (در صورت قطعی)",
        "rm_http": "حذف خودکار http:// از ورودی",
        "rm_www": "حذف خودکار .www از ورودی",
        "smart_ip": "فیلتر آی‌پی‌های داخلی و نامعتبر",
        "strict_ping": "حالت سخت‌گیرانه (الزام دریافت پینگ سالم)",
        "auto_scroll": "اسکرول خودکار جدول هنگام اسکن",
        "auto_save": "ساخت خودکار config.json پس از اتمام",
        "port_scan_mode": "فعال‌سازی حالت اسکنر پورت (یافتن پورت‌های باز سرور)",
        "btn_save": "💾 ذخیره تنظیمات", "btn_stop": "توقف", "btn_start": "🚀 شروع رادار",
        "stat_scans": "تست‌های انجام شده", "stat_success": "موفق (متصل)", "stat_ping": "فقط پینگ", "stat_down": "مسدود / خطا",
        "btn_export_json": "ساخت config.json", "btn_export_csv": "خروجی گروهی (CSV)", "btn_export_custom": "⚙ خروجی سفارشی",
        "lbl_sort": "برای مرتب‌سازی روی عنوان ستون‌ها کلیک کنید",
        "col_select": "تیک", "col_target": "تارگت", "col_ip": "آی‌پی", "col_port": "پورت", "col_icmp": "پینگ و جیتر", "col_tcp": "TCP پینگ", "col_sni_http": "وضعیت اتصال", "col_cdn": "شبکه (CDN)", "col_speed": "سرعت", "col_score": "امتیاز (100)", "col_status": "وضعیت",
        "ready": "رادار آماده اسکن شبکه است...",
        "msg_error": "خطا", "msg_success": "موفقیت", "msg_warning": "هشدار", "msg_info": "پیام",
        "msg_no_target": "تارگت معتبری در ورودی یافت نشد.",
        "msg_copied": "در کلیپ‌بورد کپی شد.", "msg_empty_clipboard": "کلیپ‌بورد خالی است.",
        "msg_no_select": "هیچ موردی انتخاب نشده است (☑).", "msg_invalid_select": "ردیف انتخابی، پورت باز یا اتصال معتبری ندارد.",
        "msg_saved_json": "فایل config.json ساخته شد.\n\nمسیر:", "msg_auto_saved": "بهترین سرور انتخاب و config.json آپدیت شد.",
        "msg_no_export": "داده موفقی برای خروجی وجود ندارد.", "msg_csv_saved": "فایل CSV با موفقیت ذخیره شد.", "msg_txt_saved": "فایل متنی TXT با موفقیت ذخیره شد.",
        "msg_no_filter": "هیچ سروری با این فیلترها در لیست یافت نشد.",
        "msg_scan_start": "در حال اسکن {} ترکیب شبکه...", "msg_scan_cancel": "عملیات متوقف شد. نتایج پیش‌فرض بر اساس امتیاز مرتب شدند.", "msg_scan_finish": "اسکن پایان یافت. نتایج پیش‌فرض بر اساس امتیاز مرتب شدند.",
        "st_sni_usable": "✔ اس‌ان‌آی متصل", "st_tcp_ok": "✔ پورت باز", "st_ping_only": "◐ فقط پینگ", "st_down": "✖ مسدود", "st_timeout": "تایم‌اوت", "st_filtered": "✖ فیلتر شده",
        "st_valid": "معتبر", "st_invalid": "ناموفق",
        "targets_count": "تارگت‌های یافت‌شده:",
        "time_elapsed": "سپری شده:", "time_eta": "باقی‌مانده:",
        "dlg_custom_title": "خروجی سفارشی", "dlg_fmt": ":فرمت خروجی", "dlg_status": ":وضعیت اتصال", "dlg_cdn": ":تأمین‌کننده", "dlg_btn_export": "دریافت خروجی",
        "dlg_val_all_suc": "همه موارد موفق", "dlg_val_all_cdn": "همه شبکه‌ها", "dlg_val_txt": "متنی گروه بندی شده (TXT)", "dlg_val_csv": "اکسل (CSV)",
        "upd_avail": "نسخه جدید ({}) منتشر شده است.\nآیا می‌خواهید به صفحه دانلود بروید؟", "upd_latest": "شما از آخرین نسخه استفاده می‌کنید.", "upd_not_found": "هیچ نسخه‌ای روی مخزن گیت‌هاب یافت نشد."
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
        "target_ports": "Target Ports (Comma/Newline/Dash for range):",
        "speed_url": "Speed Test Path (e.g. /10MB.bin):",
        "max_cidr": "Max CIDR Expand:",
        "threads": "Scan Speed (Threads):",
        "timeout": "Timeout (Seconds):",
        "retry_count": "Retry Count (If timeout):",
        "rm_http": "Auto remove http:// from input",
        "rm_www": "Auto remove .www from input",
        "smart_ip": "Filter Private/Invalid IPs",
        "strict_ping": "Strict Mode (Require successful Ping)",
        "auto_scroll": "Auto-scroll table during scan",
        "auto_save": "Auto-create config.json on finish",
        "port_scan_mode": "Enable Port Scanner Mode (Find open server ports)",
        "btn_save": "💾 Save Settings", "btn_stop": "Stop", "btn_start": "🚀 Start Radar",
        "stat_scans": "Scans Performed", "stat_success": "Success (Connected)", "stat_ping": "Ping Only", "stat_down": "Blocked / Error",
        "btn_export_json": "Create config.json", "btn_export_csv": "Export All (CSV)", "btn_export_custom": "⚙ Custom Export",
        "lbl_sort": "Click on column headers to sort results",
        "col_select": "Sel", "col_target": "Target", "col_ip": "IP Address", "col_port": "Port", "col_icmp": "Ping & Jitter", "col_tcp": "TCP Ping", "col_sni_http": "Connection State", "col_cdn": "Provider", "col_speed": "Speed", "col_score": "Score (100)", "col_status": "Verdict",
        "ready": "Radar is ready to scan the network...",
        "msg_error": "Error", "msg_success": "Success", "msg_warning": "Warning", "msg_info": "Info",
        "msg_no_target": "No valid targets found in input.",
        "msg_copied": "Copied to clipboard.", "msg_empty_clipboard": "Clipboard is empty.",
        "msg_no_select": "No item selected (☑).", "msg_invalid_select": "Selected row does not have a valid connection.",
        "msg_saved_json": "config.json created.\n\nPath:", "msg_auto_saved": "Best server selected and config.json updated.",
        "msg_no_export": "No successful data to export.", "msg_csv_saved": "CSV Saved successfully.", "msg_txt_saved": "TXT Saved successfully.",
        "msg_no_filter": "No results match these filters.",
        "msg_scan_start": "Scanning {} combinations...", "msg_scan_cancel": "Cancelled. Results sorted by Score.", "msg_scan_finish": "Finished. Results sorted by Score.",
        "st_sni_usable": "✔ SNI Usable", "st_tcp_ok": "✔ Port Open", "st_ping_only": "◐ Ping Only", "st_down": "✖ Blocked", "st_timeout": "Timeout", "st_filtered": "✖ Filtered",
        "st_valid": "Valid", "st_invalid": "Failed",
        "targets_count": "Parsed Targets:",
        "time_elapsed": "Elapsed:", "time_eta": "ETA:",
        "dlg_custom_title": "Custom Export", "dlg_fmt": "Format:", "dlg_status": "Connection Status:", "dlg_cdn": "Provider:", "dlg_btn_export": "Export File",
        "dlg_val_all_suc": "All Success", "dlg_val_all_cdn": "All CDNs", "dlg_val_txt": "Beautiful Grouped (TXT)", "dlg_val_csv": "Excel (CSV)",
        "upd_avail": "New version ({}) is available.\nDo you want to open the download page?", "upd_latest": "You are using the latest version.", "upd_not_found": "No releases found on GitHub repository."
    }
}

class SNIScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1400x900")
        
        self.current_lang = "fa"
        self.theme_state = 0 
        
        self.font_main = ("Tahoma", 9)
        self.font_bold = ("Tahoma", 9, "bold")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.is_scanning = False
        self.executor = None
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        
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

        self.text_input = tk.Text(self.right_panel, width=40, height=8, font=("Consolas", 10))
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
        self.threads_var = tk.IntVar(value=30)
        ttk.Entry(self.settings_frame, textvariable=self.threads_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_threads = ttk.Label(self.settings_frame)
        self.lbl_set_threads.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Entry(self.settings_frame, textvariable=self.timeout_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_timeout = ttk.Label(self.settings_frame)
        self.lbl_set_timeout.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.retry_count_var = tk.IntVar(value=1)
        ttk.Entry(self.settings_frame, textvariable=self.retry_count_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=5)
        self.lbl_set_retry = ttk.Label(self.settings_frame)
        self.lbl_set_retry.grid(row=row_idx, column=1, sticky="e", padx=5, pady=5)

        row_idx += 1
        self.port_scan_var = tk.BooleanVar(value=False)
        self.chk_port_scan = ttk.Checkbutton(self.settings_frame, variable=self.port_scan_var)
        self.chk_port_scan.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.strict_ping_var = tk.BooleanVar(value=False)
        self.chk_strict_ping = ttk.Checkbutton(self.settings_frame, variable=self.strict_ping_var)
        self.chk_strict_ping.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.smart_ip_var = tk.BooleanVar(value=True)
        self.chk_smart_ip = ttk.Checkbutton(self.settings_frame, variable=self.smart_ip_var)
        self.chk_smart_ip.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.remove_http_var = tk.BooleanVar(value=False)
        self.chk_rm_http = ttk.Checkbutton(self.settings_frame, variable=self.remove_http_var)
        self.chk_rm_http.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.remove_www_var = tk.BooleanVar(value=False)
        self.chk_rm_www = ttk.Checkbutton(self.settings_frame, variable=self.remove_www_var)
        self.chk_rm_www.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self.chk_auto_scroll = ttk.Checkbutton(self.settings_frame, variable=self.auto_scroll_var)
        self.chk_auto_scroll.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_save_var = tk.BooleanVar(value=False)
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

        self.dash_frame = tk.Frame(self.left_panel)
        self.dash_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        self.stat_frames = []
        self.lbl_stat_total_val, self.lbl_stat_total_title = self.create_metric_card(self.dash_frame, "#e9ecef", "#495057")
        self.lbl_stat_success_val, self.lbl_stat_success_title = self.create_metric_card(self.dash_frame, "#d1e7dd", "#0f5132")
        self.lbl_stat_ping_val, self.lbl_stat_ping_title = self.create_metric_card(self.dash_frame, "#cff4fc", "#055160")
        self.lbl_stat_down_val, self.lbl_stat_down_title = self.create_metric_card(self.dash_frame, "#f8d7da", "#842029")

        progress_frame = ttk.Frame(self.left_panel)
        progress_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        progress_frame.columnconfigure(1, weight=1)

        self.lbl_progress_pct = ttk.Label(progress_frame, text="0%", font=self.font_bold, width=5)
        self.lbl_progress_pct.grid(row=0, column=0, sticky="w", padx=(0,5))
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=5)
        self.lbl_time_info = ttk.Label(progress_frame, text="", font=("Consolas", 8))
        self.lbl_time_info.grid(row=0, column=2, sticky="e", padx=(5,0))

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

        btn_scroll_down = ttk.Button(tools_frame, text="⬇️", width=3, command=lambda: self.tree.yview_moveto(1))
        btn_scroll_down.pack(side="right", padx=2)
        btn_scroll_up = ttk.Button(tools_frame, text="⬆️", width=3, command=lambda: self.tree.yview_moveto(0))
        btn_scroll_up.pack(side="right", padx=2)
        self.lbl_sort_guide = ttk.Label(tools_frame, font=("Tahoma", 8))
        self.lbl_sort_guide.pack(side="right", padx=10)

        # جدول نتایج پیشرفته‌تر
        columns = ("select", "target", "ip", "port", "icmp", "tcp_ping", "sni_http", "cdn", "speed", "score", "status")
        self.tree = ttk.Treeview(self.left_panel, columns=columns, show="headings")
        
        self.tree.column("select", width=40, anchor="center")
        self.tree.column("target", width=120, anchor="w")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("port", width=50, anchor="center")
        self.tree.column("icmp", width=110, anchor="center") # برای نمایش گراف
        self.tree.column("tcp_ping", width=70, anchor="center")
        self.tree.column("sni_http", width=100, anchor="center")
        self.tree.column("cdn", width=100, anchor="center")
        self.tree.column("speed", width=80, anchor="center")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("status", width=100, anchor="center")

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
        self.lbl_set_retry.configure(text=t["retry_count"])
        
        self.chk_port_scan.configure(text=t["port_scan_mode"])
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
                         ("icmp","col_icmp"), ("tcp_ping","col_tcp"), ("sni_http","col_sni_http"), ("cdn","col_cdn"), 
                         ("speed","col_speed"), ("score","col_score"), ("status","col_status")]:
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
        t = LANG[self.current_lang]
        try:
            req = urllib.request.Request(GITHUB_API_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                latest_version = data.get("tag_name", VERSION)
                if latest_version != VERSION:
                    if messagebox.askyesno("Update Available", t["upd_avail"].format(latest_version)):
                        webbrowser.open(data.get("html_url", ""))
                else:
                    messagebox.showinfo("Up to date", t["upd_latest"])
        except Exception:
            messagebox.showinfo("Info", t["upd_not_found"])

    def save_settings(self):
        settings = {
            "targets": self.text_input.get("1.0", tk.END).strip(),
            "ports": self.ports_input.get("1.0", tk.END).strip(),
            "default_sni": self.default_sni_var.get(),
            "speed_url": self.speed_url_var.get(),
            "cidr_limit": self.cidr_limit_var.get(),
            "threads": self.threads_var.get(),
            "timeout": self.timeout_var.get(),
            "retry_count": self.retry_count_var.get(),
            "port_scan": self.port_scan_var.get(),
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
            messagebox.showinfo(LANG[self.current_lang]["msg_success"], LANG[self.current_lang]["btn_save"])
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
            self.threads_var.set(settings.get("threads", 30))
            self.timeout_var.set(settings.get("timeout", 2.0))
            self.retry_count_var.set(settings.get("retry_count", 1))
            self.port_scan_var.set(settings.get("port_scan", False))
            
            self.remove_http_var.set(settings.get("remove_http", False))
            self.remove_www_var.set(settings.get("remove_www", False))
            self.smart_ip_var.set(settings.get("smart_ip", True))
            self.strict_ping_var.set(settings.get("strict_ping", False))
            self.auto_scroll_var.set(settings.get("auto_scroll", True))
            self.auto_save_var.set(settings.get("auto_save", False))
            
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
        if col in ("icmp", "tcp_ping", "speed", "port", "score"):
            def extract_number(val):
                nums = re.findall(r'\d+\.?\d*', str(val))
                return float(nums[0]) if nums else (999999.0 if col in ("icmp", "tcp_ping") else 0.0)
            l.sort(key=lambda t: extract_number(t[0]), reverse=reverse)
        else:
            l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.treeview_sort_column(col, not reverse))

    def sort_results_by_default(self):
        self.treeview_sort_column("score", True)

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
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, name in COMPILED_SUBNETS:
                if ip_obj in net:
                    return name
        except ValueError:
            pass
        return "Unknown" if self.current_lang=="en" else "نامشخص"

    def icmp_ping(self, ip, timeout):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        t_param = '-w' if platform.system().lower() == 'windows' else '-W'
        t_val = str(int(timeout * 1000)) if platform.system().lower() == 'windows' else str(max(1, int(timeout)))
        cmd =['ping', param, '1', t_param, t_val, ip]
        kwargs = {'creationflags': 0x08000000} if platform.system().lower() == 'windows' else {}
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1, **kwargs)
            if res.returncode == 0:
                match = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)', res.stdout, re.IGNORECASE)
                if match: return True, float(match.group(1))
                return True, 1.0
        except Exception:
            pass
        return False, None

    def sparkline(self, data):
        """تولید نمودار خطی کوچک متنی بر اساس لیستی از پینگ‌ها"""
        if not data: return ""
        bars = " ▂▃▄▅▆▇█"
        mx = max(data)
        if mx == 0: return bars[0] * len(data)
        return "".join(bars[int(v / mx * 7)] for v in data)

    def calculate_score(self, ping, tcp, tls_ok, tcp_ok, speed, jitter):
        """فرمول هوشمند برای امتیازدهی سرور (0 تا 100)"""
        score = 0
        if tls_ok: score += 40
        elif tcp_ok: score += 20
        
        if tcp_ok and ping:
            if ping < 100: score += 25
            elif ping < 200: score += 15
            elif ping < 350: score += 5
            
        if jitter is not None:
            if jitter < 10: score += 15
            elif jitter < 30: score += 10
            elif jitter < 70: score += 5
            
        if speed > 0:
            if speed > 500: score += 20
            elif speed > 100: score += 10
            elif speed > 20: score += 5
            
        return min(100, max(0, score))

    def parse_ports_input(self, raw_text):
        ports = []
        raw_text = raw_text.replace('\n', ',')
        for part in raw_text.split(','):
            part = part.strip()
            if not part: continue
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                p = int(part)
                if 0 < p <= 65535: ports.append(p)
        return sorted(list(set(ports)))

    def parse_targets_smart(self, raw_text):
        targets = []
        max_limit = 50000
        cleaned_text = re.sub(r'(?i)(vless|vmess|trojan|ss|ssr)://', ' ', raw_text)
        if self.remove_http_var.get(): cleaned_text = re.sub(r'(?i)https?://', ' ', cleaned_text)
        if self.remove_www_var.get(): cleaned_text = re.sub(r'(?i)www\.', ' ', cleaned_text)

        tokens = re.split(r'[\s,]+', cleaned_text)
        for token in tokens:
            if not token or len(targets) >= max_limit: continue
            port = None
            host = token
            port_match = re.search(r':(\d{1,5})$', token)
            if port_match and not token.endswith(']'): 
                port = int(port_match.group(1))
                host = token[:port_match.start()]
            host = host.strip('[]')

            try:
                if '/' in host:
                    net = ipaddress.ip_network(host, strict=False)
                    for ip in list(net.hosts())[:self.cidr_limit_var.get()]:
                        targets.append({"host": str(ip), "port": port})
                        if len(targets) >= max_limit: break
                    continue
            except ValueError: pass

            try:
                ipaddress.ip_address(host)
                targets.append({"host": host, "port": port})
                continue
            except ValueError: pass

            if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', host):
                targets.append({"host": host, "port": port})

        unique_targets = []
        seen = set()
        for t in targets:
            identifier = f"{t['host']}:{t['port']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_targets.append(t)
        return unique_targets

    def scan_worker(self, task):
        if self.stop_event.is_set(): return
        
        target_label = task["target_label"]
        test_host = task["host"]
        sni_to_use = task["sni"]
        port = task["port"]
        timeout_val = self.timeout_var.get()
        strict_ping = self.strict_ping_var.get()
        retry_max = max(1, self.retry_count_var.get())
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
                'target': target_label, 'ip': '-', 'port': port, 'icmp': '-', 'tcp_ping': '-',
                'sni_http': '-', 'cdn': '-', 'speed': '-', 'score': 0, 'status': 'DNS Error', 'cat': 'down'
            })
            return

        for ip in valid_ips:
            if self.stop_event.is_set(): return
            cdn_name = self.detect_cdn(ip)
            
            # --- 1. ICMP Ping with Retry & Jitter ---
            ping_history = []
            icmp_ok = False
            for _ in range(retry_max):
                ok, ms = self.icmp_ping(ip, timeout_val)
                if ok: 
                    icmp_ok = True
                    ping_history.append(ms)
                elif retry_max > 1:
                    ping_history.append(0) # 0 means timeout for sparkline
                    
            if strict_ping and not icmp_ok:
                self.result_queue.put({
                    'target': target_label, 'ip': ip, 'port': port, 'icmp': t["st_timeout"], 'tcp_ping': '-',
                    'sni_http': '-', 'cdn': cdn_name, 'speed': '-', 'score': 0, 'status': t["st_filtered"], 'cat': 'down'
                })
                continue
                
            ping_avg = round(sum(p for p in ping_history if p>0) / max(1, len([p for p in ping_history if p>0])), 1) if icmp_ok else None
            jitter = round(statistics.stdev(p for p in ping_history if p>0), 1) if len([p for p in ping_history if p>0]) > 1 else None
            
            spark = self.sparkline(ping_history) if retry_max > 1 and icmp_ok else ""
            icmp_display = f"{ping_avg}ms {spark}" if icmp_ok else t["st_timeout"]

            # --- 2. TCP & HTTP Check ---
            tcp_ok = False
            tcp_ms = None
            tls_ok = False
            http_status = "-"
            speed_kb = 0.0
            
            try:
                start_tcp = time.perf_counter()
                with socket.create_connection((ip, port), timeout=timeout_val) as sock:
                    tcp_ms = round((time.perf_counter() - start_tcp) * 1000, 1)
                    tcp_ok = True
                    
                    req_path = self.speed_url_var.get().strip()
                    if not req_path.startswith('/'): req_path = '/' + req_path
                    
                    if port in [443, 8443, 2053, 2083, 2087, 2096]:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with ctx.wrap_socket(sock, server_hostname=sni_to_use) as ssock:
                            tls_ok = True
                            req = f"GET {req_path} HTTP/1.1\r\nHost: {sni_to_use}\r\nConnection: close\r\n\r\n"
                            start_dl = time.time()
                            ssock.sendall(req.encode())
                            bytes_recv = 0
                            first_chunk = True
                            while True:
                                data = ssock.recv(4096)
                                if not data: break
                                if first_chunk:
                                    header = data.split(b'\r\n')[0].decode(errors='ignore')
                                    if header.startswith('HTTP'): http_status = header.split(' ', 1)[-1]
                                    first_chunk = False
                                bytes_recv += len(data)
                                if time.time() - start_dl > 1.0: break
                            speed_kb = round((bytes_recv / 1024) / max(time.time() - start_dl, 0.001), 1)
                    else:
                        req = f"GET {req_path} HTTP/1.1\r\nHost: {sni_to_use}\r\nConnection: close\r\n\r\n"
                        start_dl = time.time()
                        sock.sendall(req.encode())
                        bytes_recv = 0
                        first_chunk = True
                        while True:
                            data = sock.recv(4096)
                            if not data: break
                            if first_chunk:
                                header = data.split(b'\r\n')[0].decode(errors='ignore')
                                if header.startswith('HTTP'): http_status = header.split(' ', 1)[-1]
                                first_chunk = False
                            bytes_recv += len(data)
                            if time.time() - start_dl > 1.0: break
                        speed_kb = round((bytes_recv / 1024) / max(time.time() - start_dl, 0.001), 1)
            except Exception:
                pass

            # --- 3. Result formatting ---
            score_val = self.calculate_score(ping_avg, tcp_ms, tls_ok, tcp_ok, speed_kb, jitter)
            sni_http_display = http_status if http_status != "-" else (t["st_valid"] if tls_ok else (t["st_invalid"] if tcp_ok else '-'))

            if tls_ok: status, cat = t["st_sni_usable"], "success"
            elif tcp_ok: status, cat = t["st_tcp_ok"], "success"
            elif icmp_ok: status, cat = t["st_ping_only"], "ping_only"
            else: status, cat = t["st_down"], "down"

            self.result_queue.put({
                'target': target_label, 'ip': ip, 'port': port, 
                'icmp': icmp_display, 
                'tcp_ping': f"{tcp_ms} ms" if tcp_ok else "-",
                'sni_http': sni_http_display, 
                'cdn': cdn_name, 'speed': f"{speed_kb} KB/s" if speed_kb>0 else "-", 
                'score': score_val, 'status': status, 'cat': cat, 'sni_used': sni_to_use
            })

    def start_scan(self):
        raw_text = self.text_input.get("1.0", tk.END)
        default_sni = self.default_sni_var.get().strip()
        t = LANG[self.current_lang]
        
        parsed_ports = self.parse_ports_input(self.ports_input.get("1.0", tk.END))
        if not parsed_ports: parsed_ports = [443]

        parsed_targets = self.parse_targets_smart(raw_text)
        if not parsed_targets:
            messagebox.showwarning(t["msg_error"], t["msg_no_target"])
            return

        tasks =[]
        unique_targets_count = set()
        
        # اگر کاربر تیک اسکنر پورت را زده باشد، تمام پورت‌ها را روی تمام تارگت‌ها تست می‌کنیم
        force_port_scan = self.port_scan_var.get()
        
        for p_target in parsed_targets:
            host = p_target["host"]
            specific_port = p_target["port"]
            ports_to_scan = parsed_ports if force_port_scan or not specific_port else [specific_port]
            
            unique_targets_count.add(host)
            
            try:
                ipaddress.ip_address(host)
                sni_to_use = default_sni
            except ValueError:
                sni_to_use = host

            for p in ports_to_scan:
                tasks.append({
                    "target_label": host,
                    "host": host,
                    "sni": sni_to_use,
                    "port": p
                })

        for item in self.tree.get_children(): self.tree.delete(item)

        self.stat_unique_targets = len(unique_targets_count)
        self.stat_total_scans = len(tasks)
        self.stat_checked = 0
        self.stat_success = 0
        self.stat_ping_only = 0
        self.stat_down = 0
        self.progress_bar["value"] = 0
        self.lbl_progress_pct.configure(text="0%")
        
        self.lbl_targets_count.configure(text=f"{t['targets_count']} {self.stat_unique_targets}")
        self.update_metrics_ui()

        self.is_scanning = True
        self.start_time = time.time()
        self.stop_event.clear()
        
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export_json.configure(state="disabled")
        self.btn_export_csv.configure(state="disabled")
        self.btn_export_custom.configure(state="disabled")
        
        self.lbl_status.configure(text=t["msg_scan_start"].format(self.stat_total_scans))

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
            
            # Colorize score
            score = res['score']
            score_display = f"{score} 🟩" if score > 70 else (f"{score} 🟨" if score > 30 else f"{score} 🟥")
            
            tag = res['cat']
            item_id = self.tree.insert("", tk.END, values=(
                "☐", res['target'], res['ip'], res['port'], res['icmp'], res['tcp_ping'],
                res['sni_http'], res['cdn'], res['speed'], score_display, res['status']
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
        t = LANG[self.current_lang]
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_export_json.configure(state="normal")
        self.btn_export_csv.configure(state="normal")
        self.btn_export_custom.configure(state="normal")
        
        self.progress_bar["value"] = 100
        self.lbl_progress_pct.configure(text="100%")
        
        self.sort_results_by_default()
        
        if self.stop_event.is_set():
            self.lbl_status.configure(text=t["msg_scan_cancel"])
        else:
            self.lbl_status.configure(text=t["msg_scan_finish"])
        
        if self.auto_save_var.get():
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                if "✔" in vals[10]:
                    self._check_item(child)
                    self.export_config(auto=True)
                    break

    def export_config(self, auto=False):
        t = LANG[self.current_lang]
        selected_item = None
        for child in self.tree.get_children():
            if self.tree.item(child, "values")[0] == "☑":
                selected_item = child
                break
                
        if not selected_item:
            if not auto: messagebox.showwarning(t["msg_warning"], t["msg_no_select"])
            return

        vals = self.tree.item(selected_item, "values")
        if "✔" not in vals[10]:
            if not auto: messagebox.showwarning(t["msg_warning"], t["msg_invalid_select"])
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
            if not auto: messagebox.showinfo(t["msg_success"], f"{t['msg_saved_json']} {os.path.abspath('config.json')}")
            else: self.lbl_status.configure(text=t["msg_auto_saved"])
        except Exception as e:
            if not auto: messagebox.showerror(t["msg_error"], str(e))

    def export_csv(self):
        t = LANG[self.current_lang]
        valid_items =[]
        for child in self.tree.get_children():
            vals = self.tree.item(child, "values")
            sni_used = self.tree.item(child, "text")
            if "✔" in vals[10] or "◐" in vals[10]:
                valid_items.append([vals[1], vals[2], vals[3], vals[4], vals[5], sni_used, vals[6], vals[7], vals[8], vals[9], vals[10]])

        if not valid_items:
            messagebox.showwarning(t["msg_warning"], t["msg_no_export"])
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Radar_Export.csv")
        if not path: return

        try:
            with open(path, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                headers = [t[k] for k in ["col_target", "col_ip", "col_port", "col_icmp", "col_tcp", "col_sni_http", "col_cdn", "col_speed", "col_score", "col_status"]]
                headers.insert(5, "Used SNI" if self.current_lang=="en" else "SNI استفاده شده")
                writer.writerow(headers)
                writer.writerows(valid_items)
            messagebox.showinfo(t["msg_success"], t["msg_csv_saved"])
        except Exception as e:
            messagebox.showerror(t["msg_error"], str(e))

    def open_custom_export_dialog(self):
        t = LANG[self.current_lang]
        top = tk.Toplevel(self.root)
        top.title(t["dlg_custom_title"])
        top.geometry("400x320")
        top.transient(self.root)
        top.grab_set()
        
        bg_col = "#000" if self.theme_state==2 else ("#212529" if self.theme_state==1 else "#f8f9fa")
        fg_col = "#a0a0a0" if self.theme_state==2 else ("white" if self.theme_state==1 else "black")
        top.configure(bg=bg_col)

        ttk.Label(top, text=t["dlg_fmt"], background=bg_col, foreground=fg_col).pack(pady=(10, 2))
        fmt_var = tk.StringVar(value=t["dlg_val_txt"])
        fmt_combo = ttk.Combobox(top, textvariable=fmt_var, state="readonly", justify="center")
        fmt_combo['values'] = (t["dlg_val_txt"], t["dlg_val_csv"])
        fmt_combo.pack(fill="x", padx=40)

        ttk.Label(top, text=t["dlg_status"], background=bg_col, foreground=fg_col).pack(pady=(15, 2))
        status_var = tk.StringVar(value=t["dlg_val_all_suc"])
        status_combo = ttk.Combobox(top, textvariable=status_var, state="readonly", justify="center")
        status_combo['values'] = (t["dlg_val_all_suc"], t["st_sni_usable"], t["st_tcp_ok"], t["st_ping_only"])
        status_combo.pack(fill="x", padx=40)

        ttk.Label(top, text=t["dlg_cdn"], background=bg_col, foreground=fg_col).pack(pady=(15, 2))
        cdn_var = tk.StringVar(value=t["dlg_val_all_cdn"])
        cdn_combo = ttk.Combobox(top, textvariable=cdn_var, state="readonly", justify="center")
        cdn_combo['values'] = (t["dlg_val_all_cdn"], "Cloudflare", "Vercel", "Fastly", "Akamai", "Google Cloud", "AWS", "ArvanCloud", "Unknown", "نامشخص")
        cdn_combo.pack(fill="x", padx=40)

        def perform_custom_export():
            st_filter = status_var.get()
            cdn_filter = cdn_var.get()
            export_fmt = fmt_var.get()
            
            valid_items = []
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                sni_used = self.tree.item(child, "text")
                
                if st_filter == t["dlg_val_all_suc"]:
                    if "✖" in vals[10] or "Error" in vals[10] or "خطا" in vals[10]: continue
                else:
                    if st_filter not in vals[10]: continue
                
                if cdn_filter != t["dlg_val_all_cdn"]:
                    if cdn_filter not in vals[7]: continue

                valid_items.append({
                    "target": vals[1], "ip": vals[2], "port": vals[3], "icmp": vals[4], "tcp": vals[5],
                    "sni_http": vals[6], "cdn": vals[7], "speed": vals[8], "score": vals[9], "status": vals[10], "sni_used": sni_used
                })

            if not valid_items:
                messagebox.showwarning(t["msg_warning"], t["msg_no_filter"], parent=top)
                return
            
            if "CSV" in export_fmt or "اکسل" in export_fmt:
                path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Custom_Export.csv", parent=top)
                if not path: return
                try:
                    with open(path, mode='w', newline='', encoding='utf-8-sig') as f:
                        writer = csv.writer(f)
                        headers = [t[k] for k in ["col_target", "col_ip", "col_port", "col_icmp", "col_tcp", "col_sni_http", "col_cdn", "col_speed", "col_score", "col_status"]]
                        headers.insert(5, "Used SNI" if self.current_lang=="en" else "SNI استفاده شده")
                        writer.writerow(headers)
                        for r in valid_items:
                            writer.writerow([r["target"], r["ip"], r["port"], r["icmp"], r["tcp"], r["sni_used"], r["sni_http"], r["cdn"], r["speed"], r["score"], r["status"]])
                    messagebox.showinfo(t["msg_success"], t["msg_csv_saved"], parent=top)
                    top.destroy()
                except Exception as e:
                    messagebox.showerror(t["msg_error"], str(e), parent=top)
            else:
                path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")], initialfile="Beautiful_Export.txt", parent=top)
                if not path: return
                try:
                    with open(path, mode='w', encoding='utf-8') as f:
                        f.write(f"# Advanced SNI Radar {VERSION} - Custom Export\n")
                        f.write(f"# Filter Status: {st_filter} | Filter CDN: {cdn_filter}\n")
                        f.write(f"# Total Results: {len(valid_items)}\n\n")
                        
                        both = [r for r in valid_items if t["st_sni_usable"] in r["status"]]
                        tcp_only = [r for r in valid_items if t["st_tcp_ok"] in r["status"]]
                        ping_only = [r for r in valid_items if t["st_ping_only"] in r["status"]]
                        
                        if both:
                            f.write("=== 🚀 FULL CONNECTED (TLS/HTTP OK) ===\n")
                            for r in sorted(both, key=lambda x: int(x["score"].split()[0]) if x["score"] else 0, reverse=True):
                                f.write(f"{r['target']}  ->  {r['ip']}:{r['port']}  [Score: {r['score']} | Ping/Jitter: {r['icmp']} | Speed: {r['speed']} | CDN: {r['cdn']}]\n")
                            f.write("\n")
                            
                        if tcp_only:
                            f.write("=== 🔓 TCP OPEN (No TLS/HTTP) ===\n")
                            for r in sorted(tcp_only, key=lambda x: int(x["score"].split()[0]) if x["score"] else 0, reverse=True):
                                f.write(f"{r['target']}  ->  {r['ip']}:{r['port']}  [Score: {r['score']} | TCP Ping: {r['tcp']} | CDN: {r['cdn']}]\n")
                            f.write("\n")
                            
                        if ping_only:
                            f.write("=== 📡 ICMP PING ONLY (Port Closed) ===\n")
                            for r in sorted(ping_only, key=lambda x: int(x["score"].split()[0]) if x["score"] else 0, reverse=True):
                                f.write(f"{r['target']}  ->  {r['ip']}  [Score: {r['score']} | ICMP: {r['icmp']} | CDN: {r['cdn']}]\n")
                            f.write("\n")
                            
                    messagebox.showinfo(t["msg_success"], t["msg_txt_saved"], parent=top)
                    top.destroy()
                except Exception as e:
                    messagebox.showerror(t["msg_error"], str(e), parent=top)

        btn_save = ttk.Button(top, text=t["dlg_btn_export"], style="Primary.TButton", command=perform_custom_export)
        btn_save.pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = SNIScannerApp(root)
    root.mainloop()
