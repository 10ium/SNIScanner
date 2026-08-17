import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Menu
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
import struct
import subprocess
import platform
import webbrowser
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import statistics
import random
import math

# ==============================================================================
# ۱. تنظیمات، متغیرهای پایه و دیتابیس شبکه‌ها و کدهای HTTP
# ==============================================================================
VERSION = "v2.3.0-PRO"
GITHUB_API_URL = "https://api.github.com/repos/10ium/SNIScanner/releases/latest"
SETTINGS_FILE = "radar_settings.json"

CDN_RANGES = [
    ("Cloudflare", [
        "1.0.0.0/24", "1.1.1.0/24", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
        "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    ]),
    ("Google Cloud", [
        "8.8.4.0/24", "8.8.8.0/24", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19",
        "74.125.0.0/16", "104.132.0.0/14", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16",
        "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
        "34.143.0.0/24", "34.160.0.0/24", "34.96.0.0/24", "35.186.0.0/24", "35.201.0.0/24", "34.117.0.0/24",
        "2001:4860::/32", "2600:1900::/28", "2a00:1450::/32"
    ]),
    ("Fastly", [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "104.156.80.0/20", "146.75.0.0/16",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "199.27.72.0/21", "199.232.0.0/16",
        "2a04:4e40::/32", "2a04:4e42::/32"
    ]),
    ("Akamai", [
        "2.16.0.0/13", "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "23.192.0.0/11",
        "63.0.0.0/8", "69.192.0.0/16", "72.246.0.0/15", "88.221.0.0/16", "95.100.0.0/15", "104.64.0.0/10",
        "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14", "2.17.0.0/24", "2.18.0.0/24", "2.19.0.0/24",
        "2.20.0.0/24", "2.21.0.0/24", "2.22.0.0/24", "23.48.0.0/24", "23.58.0.0/24", "23.193.0.0/24",
        "23.202.0.0/24", "23.43.0.0/24", "104.65.0.0/24", "104.103.0.0/24", "104.112.0.0/24",
        "184.86.0.0/24", "185.200.232.0/24", "92.16.0.0/24", "92.122.0.0/24", "2600:1400::/24"
    ]),
    ("Netlify", [
        "3.33.128.0/17", "13.32.0.0/15", "13.35.0.0/16", "18.64.0.0/14", "44.226.105.0/24",
        "50.7.4.0/24", "50.7.85.0/24", "50.7.87.0/24", "44.235.184.0/24", "52.84.0.0/15",
        "35.157.26.0/24", "63.176.8.0/24", "54.182.0.0/16", "99.83.128.0/17", "162.159.128.0/20"
    ]),
    ("Vercel", [
        "64.29.17.0/24", "64.29.18.0/24", "64.29.19.0/24", "66.33.60.0/24", "66.33.61.0/24",
        "76.76.21.0/24", "76.223.126.0/24"
    ]),
    ("CloudFront", [
        "52.46.0.0/18", "52.84.0.0/15", "54.182.0.0/16", "99.84.0.0/16", "130.176.0.0/17",
        "13.32.0.0/24", "13.35.0.0/24", "54.230.0.0/24", "143.204.0.0/24", "205.251.192.0/24",
        "54.239.128.0/24", "2600:9000::/28"
    ]),
    ("BunnyCDN", ["89.187.160.0/19", "147.75.0.0/16", "2400:52e0::/32"]),
    ("Gcore", ["92.223.0.0/16", "95.85.0.0/16", "185.158.0.0/16", "2a03:90c0::/29"]),
    ("ArvanCloud", [
        "2.144.3.128/28", "37.32.16.0/27", "37.32.17.0/27", "37.32.18.0/27", "37.32.19.0/27",
        "94.101.182.0/27", "178.131.120.48/28", "185.143.232.0/22", "185.215.232.0/22", "188.229.116.16/30"
    ]),
    ("DerakCloud", [
        "5.145.115.0/24", "5.145.118.0/23", "45.63.43.128/28", "45.77.87.48/28", "89.222.113.80/28",
        "116.202.90.176/28", "159.69.229.224/28", "165.232.92.112/28", "178.62.222.208/28", "185.24.252.192/27",
        "185.24.254.64/27", "185.24.255.192/27", "185.24.255.224/28", "192.168.204.48/28", "207.148.25.64/28",
        "2a01:4f8:c0:2da6::/64", "2a04:2f00:1:185f::/64", "2a04:2f00:2:185f::/64", "2a04:2f00:3:185f::/64",
        "2a04:2f00:ff01::/64", "2a04:2f00:ff02::/64", "2a04:2f00:ff03::/64", "2a04:2f00:ff06::/64",
        "2a04:2f00:ff08::/64", "2a04:2f00:ff09::/64"
    ]),
    ("IranServer", [
        "5.182.45.23/32", "5.182.45.37/32", "45.159.114.11/32", "87.98.249.55/32", "93.127.182.21/32",
        "93.127.182.24/32", "94.143.229.14/32", "94.182.97.44/31", "94.182.97.46/32", "168.119.4.117/32",
        "185.116.162.15/32", "185.116.162.19/32"
    ]),
    ("ParsPack", [
        "2.144.23.191/32", "5.135.72.112/28", "5.160.143.64/28", "31.214.248.208/28", "45.32.131.160/28",
        "45.32.154.64/28", "45.76.132.16/28", "45.77.211.208/28", "45.77.211.240/28", "45.77.223.80/28",
        "45.139.11.240/28", "46.20.41.224/28", "64.176.15.176/28", "64.176.64.80/28", "65.20.72.128/28",
        "65.20.113.240/28", "77.237.66.128/28", "79.175.148.128/28", "84.17.42.224/28", "87.236.161.96/28",
        "89.36.162.32/28", "89.187.169.48/28", "91.228.186.48/28", "94.182.153.64/28", "95.179.140.112/28",
        "95.179.164.96/28", "95.179.220.128/28", "95.179.254.176/28", "95.211.188.240/28", "95.211.219.96/28",
        "95.211.240.112/28", "95.211.250.112/28", "130.185.74.48/28", "130.185.79.128/28", "139.84.177.16/28",
        "139.84.236.0/28", "144.202.58.96/28", "144.202.78.96/28", "144.202.114.128/28", "155.138.162.96/28",
        "158.51.122.240/28", "158.247.223.48/28", "167.179.93.112/28", "171.22.26.240/28", "178.22.120.192/28",
        "185.8.173.0/28", "185.8.174.144/28", "185.8.175.208/28", "185.110.191.240/28", "185.204.197.0/28",
        "185.208.175.144/28", "194.5.188.32/28", "195.88.208.176/28", "195.181.174.64/28", "195.248.241.160/28",
        "195.248.242.192/28", "199.247.3.16/28", "207.148.69.96/28", "208.85.22.32/28", "213.183.48.16/28",
        "216.238.117.0/28", "217.197.97.48/28"
    ])
]

COMPILED_SUBNETS = []
for cdn_name, subnets in CDN_RANGES:
    for sub in subnets:
        try:
            COMPILED_SUBNETS.append((ipaddress.ip_network(sub, strict=False), cdn_name))
        except ValueError:
            pass

FALLBACK_DNS = {
    "cloudflare.com": ["104.16.132.229", "104.16.133.229"],
    "vercel.com": ["76.76.21.21", "198.169.2.193"],
    "nextjs.org": ["216.230.86.65"],
    "npmjs.com": ["104.17.134.117"],
    "react.dev": ["66.33.60.193"],
}

DEFAULT_PORTS = "80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443"

SPEED_TEST_PRESETS = [
    ("/cdn-cgi/trace", "سبک و سریع (Cloudflare Trace)"),
    ("/", "پیش‌فرض ریشه دامنه (Root Path)"),
    ("/10MB.bin", "تست استاندارد (10MB Test File)"),
    ("/50MB.bin", "تست سنگین پهنای باند (50MB High-Speed)"),
    ("/speedtest/random1000x1000.jpg", "تصویر بافری (Speedtest Asset)"),
    ("/favicon.ico", "فایل آیکون کم‌حجم (Favicon)")
]

CDN_TRANSLATIONS = {
    "Cloudflare": "کلودفلر", "Google Cloud": "گوگل کلود", "Fastly": "فستلی",
    "Akamai": "آکامای", "Netlify": "نتلیفای", "Vercel": "ورسل",
    "CloudFront": "کلودفرانت", "BunnyCDN": "بانی‌سی‌دی‌ان", "Gcore": "جی‌کور",
    "ArvanCloud": "ابرآروان", "DerakCloud": "درک‌کلود", "IranServer": "ایران‌سرور", "ParsPack": "پارس‌پک"
}

PRESETS_SNI = {
    "لیست کامل hCaptcha (کلودفلر)": "three-cust.hcaptcha.com\nstats.hcaptcha.com\nwww.hcaptcha.com\nu.hcaptcha.com\ntg.hcaptcha.com\nprimary.hcaptcha.com\npat-internal.hcaptcha.com\njobs.hcaptcha.com\nhmt-lucid-neumann.hcaptcha.com\ndashboard.hcaptcha.com\ncached-queries.hcaptcha.com\nbilling.hcaptcha.com\nassets.hcaptcha.com\napi.hcaptcha.com\nanalytics-beta.hcaptcha.com\naccounts.hcaptcha.com\na.hcaptcha.com\nstatic.cloudflareinsights.com",
    "دامنه آکامای (Akamai Edge)": "a248.e.akamai.net",
    "دامنه گوگل (Google Services)": "www.googleapis.com\nfonts.googleapis.com",
    "سایت‌های معروف ورسل (Vercel)": "react.dev\nvercel.com\nnextjs.org",
    "اس‌ان‌آی‌های تمیز بین‌المللی": "speedtest.net\nspotify.com\ntwitch.tv\nauth.openai.com",
}

# ==============================================================================
# ۲. ماژول فرمت و ترجمه کدهای وضعیت HTTP (Status Formatter)
# ==============================================================================
class HTTPStatusFormatter:
    STATUS_DICT = {
        "200": ("✔ 200 OK", "✔ ۲۰۰ موفق"),
        "204": ("✔ 204 No Content", "✔ ۲۰۴ بدون محتوا"),
        "206": ("✔ 206 Partial Content", "✔ ۲۰۶ محتوای جزئی"),
        "301": ("↗ 301 Moved Perm", "↗ ۳۰۱ انتقال دائم"),
        "302": ("↗ 302 Found/Redirect", "↗ ۳۰۲ تغییر مسیر"),
        "307": ("↗ 307 Temp Redirect", "↗ ۳۰۷ انتقال موقت"),
        "308": ("↗ 308 Perm Redirect", "↗ ۳۰۸ انتقال دائم"),
        "400": ("✖ 400 Bad Request", "✖ ۴۰۰ درخواست نامعتبر"),
        "401": ("🔒 401 Unauthorized", "🔒 ۴۰۱ غیرمجاز"),
        "403": ("⛔ 403 Forbidden", "⛔ ۴۰۳ مسدود (Forbidden)"),
        "404": ("🔍 404 Not Found", "🔍 ۴۰۴ یافت نشد"),
        "405": ("✖ 405 Not Allowed", "✖ ۴۰۵ متد غیرمجاز"),
        "429": ("⏱ 429 Rate Limited", "⏱ ۴۲۹ محدودیت درخواست"),
        "500": ("⚠ 500 Server Error", "⚠ ۵۰۰ خطای سرور"),
        "502": ("✖ 502 Bad Gateway", "✖ ۵۰۲ گیت‌وی نامعتبر"),
        "503": ("⚠ 503 Unavailable", "⚠ ۵۰۳ خارج از دسترس"),
        "504": ("⏱ 504 Gateway Timeout", "⏱ ۵۰۴ تایم‌اوت گیت‌وی"),
        "520": ("☁ 520 Cloudflare Err", "☁ ۵۲۰ خطای کلودفلر"),
        "521": ("☁ 521 Web Server Down", "☁ ۵۲۱ سرور خاموش"),
        "522": ("☁ 522 Connection Timeout", "☁ ۵۲۲ تایم‌اوت ارتباط"),
        "523": ("☁ 523 Origin Unreach", "☁ ۵۲۳ مبدأ غیرقابل دسترس"),
        "525": ("☁ 525 SSL Handshake Fail", "☁ ۵۲۵ شکست SSL")
    }

    @classmethod
    def format_status(cls, raw_code: str, lang: str = "fa") -> str:
        if not raw_code or raw_code == "-":
            return "-"
        code_match = re.search(r'\b\d{3}\b', raw_code)
        if code_match:
            code = code_match.group(0)
            if code in cls.STATUS_DICT:
                return cls.STATUS_DICT[code][1 if lang == "fa" else 0]
        return raw_code

# ==============================================================================
# ۳. سیستم چندزبانه (i18n)
# ==============================================================================
LANG = {
    "fa": {
        "title": f"رادار پیشرفته تحلیل شبکه و SNI - {VERSION}",
        "telegram": "کانال تلگرام",
        "update": "بررسی بروزرسانی",
        "lang_toggle": "English",
        "theme_0": "☀️ روشن", "theme_1": "🌙 تاریک", "theme_2": "🌑 سیاه مطلق",
        "input_label": "ورودی هوشمند (دامنه، IPv4/IPv6، رنج خط‌تیره، CIDR، کانفیگ):",
        "paste": "📋 پیست", "browse": "📁 فایل", "clear": "🗑 پاک کردن", "dedup": "✨ حذف تکراری", "shuffle": "🔀 بر هم زدن",
        "btn_range_mgr": "🌐 مدیریت رنج‌ها و تولید IP تصادفی (Ctrl+R)",
        "settings": "تنظیمات رادار و پویشگر",
        "default_sni": ":لیست SNI های هدف (هر خط یک مورد)",
        "btn_presets_sni": "🔍 لیست‌های آماده SNI",
        "target_ports": ":پورت‌های هدف (خط جدید یا کاما/خط فاصله)",
        "speed_url": ":مسیر یا پریست تست سرعت دانلود",
        "speed_duration": ":مدت‌زمان تست سرعت هر سرور (ثانیه)",
        "max_cidr": ":حداکثر بسط ترتیبی از هر رنج (Hosts)",
        "threads": ":تعداد ترد موازی (Concurrency)",
        "timeout": ":زمان انتظار پاسخ سوکت (ثانیه)",
        "retry_count": ":تعداد تلاش مجدد پینگ",
        "rm_http": "حذف خودکار http:// و .www از نام دامنه‌ها",
        "smart_ip": "فیلتر آی‌پی‌های داخلی/رزرو شده (Private & Bogon)",
        "strict_ping": "حالت سخت‌گیرانه (الزام دریافت پینگ ICMP سالم)",
        "auto_scroll": "اسکرول خودکار جدول هنگام اسکن",
        "auto_save": "ذخیره خودکار config.json پس از پایان",
        "port_scan_mode": "اسکنر پورت سریع (بررسی همه پورت‌ها برای تارگت)",
        "btn_save": "💾 ذخیره تنظیمات (Ctrl+S)", "btn_stop": "🛑 توقف (Esc)", "btn_start": "🚀 شروع رادار (F5)",
        "stat_scans": "تست‌های انجام شده", "stat_success": "موفق (متصل)", "stat_ping": "فقط پینگ", "stat_down": "مسدود / خطا",
        "btn_export_json": "ساخت config.json (Ctrl+E)", "btn_export_csv": "خروجی اکسل (Ctrl+Shift+E)", "btn_export_custom": "⚙ خروجی سفارشی",
        "lbl_sort": "برای مرتب‌سازی روی عناوین ستون‌ها کلیک کنید",
        "col_select": "تیک", "col_target": "تارگت / ورودی", "col_ip": "آدرس IP", "col_port": "پورت", "col_icmp": "پینگ ICMP", "col_tcp": "پینگ TCP", "col_sni_http": "وضعیت اتصال", "col_cdn": "شبکه (CDN)", "col_speed": "سرعت واقعی", "col_score": "امتیاز هوشمند", "col_status": "نتیجه نهایی",
        "ready": "رادار هوشمند آماده اسکن شبکه است... (F5 برای شروع)",
        "msg_error": "خطا", "msg_success": "موفقیت", "msg_warning": "هشدار", "msg_info": "پیام",
        "msg_no_target": "هیچ تارگت معتبری در ورودی یافت نشد.",
        "msg_copied": "در کلیپ‌بورد کپی شد.", "msg_empty_clipboard": "کلیپ‌بورد خالی است.",
        "msg_no_select": "هیچ ردیفی انتخاب نشده است (☑).", "msg_invalid_select": "ردیف انتخابی، اتصال معتبری ندارد.",
        "msg_saved_json": "فایل config.json ساخته شد (منطبق با ابزارهای Spoofing).\nمسیر:", "msg_auto_saved": "بهترین سرور با بالاترین سرعت انتخاب و config.json آپدیت شد.",
        "msg_no_export": "داده موفقی برای خروجی وجود ندارد.", "msg_csv_saved": "فایل CSV با موفقیت ذخیره شد.", "msg_txt_saved": "فایل متنی TXT با موفقیت ذخیره شد.",
        "msg_no_filter": "هیچ سروری با این فیلترها در لیست یافت نشد.",
        "msg_scan_start": "در حال اسکن هوشمند {} هدف شبکه...", "msg_scan_cancel": "عملیات متوقف شد. نتایج بر اساس سرعت و امتیاز مرتب شدند.", "msg_scan_finish": "اسکن پایان یافت. نتایج بر اساس سرعت و امتیاز مرتب شدند.",
        "st_sni_usable": "✔ اس‌ان‌آی متصل", "st_tcp_ok": "✔ پورت باز", "st_ping_only": "◐ فقط پینگ", "st_down": "✖ مسدود", "st_timeout": "تایم‌اوت", "st_filtered": "✖ فیلتر شده",
        "st_valid": "معتبر (TLS OK)", "st_invalid": "ناموفق", "st_unknown": "نامشخص",
        "targets_count": "تارگت‌های کشف شده:",
        "time_elapsed": "سپری شده:", "time_eta": "باقی‌مانده:", "scan_rate": "سرعت: {} تست/ثانیه",
        "dlg_custom_title": "خروجی سفارشی نتایج", "dlg_fmt": ":فرمت فایل خروجی", "dlg_status": ":وضعیت اتصال", "dlg_cdn": ":ارائه‌دهنده CDN", "dlg_btn_export": "دریافت خروجی",
        "dlg_val_all_suc": "همه موارد موفق", "dlg_val_all_cdn": "همه شبکه‌ها", "dlg_val_txt": "متنی گروه‌بندی شده (TXT)", "dlg_val_csv": "جدول اکسل (CSV)",
        "upd_avail": "نسخه جدید ({}) منتشر شده است.\nآیا مایل به باز کردن صفحه دانلود هستید؟", "upd_latest": "شما از آخرین نسخه استفاده می‌کنید.", "upd_not_found": "اطلاعات جدیدی یافت نشد.",
        "lbl_my_isp": "📡 شبکه عمومی شما:", "isp_fetching": "در حال دریافت...",
        "warn_vpn": "⚠️ IP خارج از ایران (استفاده از VPN)", "warn_iran": "🇮🇷 IP محلی ایران",
        "ctx_copy_ip": "کپی آدرس IP", "ctx_copy_ipport": "کپی IP:Port", "ctx_copy_detail": "کپی جزئیات کامل ردیف",
        
        "rmgr_title": "مدیریت رنج‌های CDN و ساخت آی‌پی تصادفی (Random IP Generator)",
        "rmgr_cdn_select": ":انتخاب ارائه‌دهنده شبکه / CDN",
        "rmgr_subnets_label": "لیست رنج‌ها و ساب‌نت‌های CIDR (قابل ویرایش):",
        "rmgr_btn_add": "➕ افزودن رنج",
        "rmgr_btn_reset": "🔄 بازیابی رنج‌های CDN",
        "rmgr_btn_load_subnets": "📥 انتقال مستقیم رنج‌های CIDR به اسکنر",
        "rmgr_mode_total": "تولید تعداد مشخص آی‌پی تصادفی از کل رنج‌ها (Total)",
        "rmgr_mode_per_range": "تولید تعداد مشخص آی‌پی تصادفی به ازای هر ساب‌نت (Per Subnet)",
        "rmgr_count_label": ":تعداد آی‌پی تصادفی",
        "rmgr_btn_generate": "🎲 ساخت آی‌پی‌های تصادفی و انتقال به اسکنر",
        "rmgr_msg_empty": "هیچ رنج معتبری در لیست وجود ندارد.",
        "rmgr_msg_success": "تعداد {} آی‌پی با موفقیت به ورودی اسکنر منتقل شد."
    },
    "en": {
        "title": f"Advanced Network & SNI Radar - {VERSION}",
        "telegram": "Telegram Channel",
        "update": "Check Updates",
        "lang_toggle": "فارسی",
        "theme_0": "☀️ Light", "theme_1": "🌙 Dark", "theme_2": "🌑 Pitch Black",
        "input_label": "Smart Input (Domains, IPv4/IPv6, Ranges, CIDR, Raw Configs):",
        "paste": "📋 Paste", "browse": "📁 File", "clear": "🗑 Clear", "dedup": "✨ Dupes", "shuffle": "🔀 Shuffle",
        "btn_range_mgr": "🌐 Range Manager & Random IP (Ctrl+R)",
        "settings": "Radar & Scanner Settings",
        "default_sni": "SNI List (One per line):",
        "btn_presets_sni": "🔍 SNI Presets",
        "target_ports": "Target Ports (Comma/Newline/Dash):",
        "speed_url": "Speed Test Path or Preset:",
        "speed_duration": "Speed Test Duration (Seconds):",
        "max_cidr": "Max Sequential Hosts per CIDR/Range:",
        "threads": "Parallel Threads (Concurrency):",
        "timeout": "Socket Timeout (Seconds):",
        "retry_count": "Ping Retry Count:",
        "rm_http": "Auto remove http:// & .www from target names",
        "smart_ip": "Filter Private & Bogon IPs",
        "strict_ping": "Strict Mode (Require healthy ICMP Ping)",
        "auto_scroll": "Auto-scroll table during scan",
        "auto_save": "Auto-create config.json on finish",
        "port_scan_mode": "Enable Port Scanner Mode",
        "btn_save": "💾 Save Settings (Ctrl+S)", "btn_stop": "🛑 Stop (Esc)", "btn_start": "🚀 Start Radar (F5)",
        "stat_scans": "Scans Done", "stat_success": "Success (Connected)", "stat_ping": "Ping Only", "stat_down": "Blocked / Error",
        "btn_export_json": "Create config.json (Ctrl+E)", "btn_export_csv": "Export All (Ctrl+Shift+E)", "btn_export_custom": "⚙ Custom Export",
        "lbl_sort": "Click column headers to sort results",
        "col_select": "Sel", "col_target": "Target", "col_ip": "IP Address", "col_port": "Port", "col_icmp": "ICMP Ping", "col_tcp": "TCP Ping", "col_sni_http": "Connection State", "col_cdn": "Provider", "col_speed": "Real Speed", "col_score": "Smart Score", "col_status": "Verdict",
        "ready": "Smart Radar is ready to probe... (Press F5 to start)",
        "msg_error": "Error", "msg_success": "Success", "msg_warning": "Warning", "msg_info": "Info",
        "msg_no_target": "No valid targets found in input.",
        "msg_copied": "Copied to clipboard.", "msg_empty_clipboard": "Clipboard is empty.",
        "msg_no_select": "No item selected (☑).", "msg_invalid_select": "Selected row does not have a valid connection.",
        "msg_saved_json": "config.json created (Compatible with Spoofing tools).\nPath:", "msg_auto_saved": "Best high-speed server selected and config.json updated.",
        "msg_no_export": "No successful data to export.", "msg_csv_saved": "CSV Saved successfully.", "msg_txt_saved": "TXT Saved successfully.",
        "msg_no_filter": "No results match these filters.",
        "msg_scan_start": "Smart scanning {} network targets...", "msg_scan_cancel": "Cancelled. Results sorted by Score & Speed.", "msg_scan_finish": "Finished. Results sorted by Score & Speed.",
        "st_sni_usable": "✔ SNI Usable", "st_tcp_ok": "✔ Port Open", "st_ping_only": "◐ Ping Only", "st_down": "✖ Blocked", "st_timeout": "Timeout", "st_filtered": "✖ Filtered",
        "st_valid": "Valid (TLS OK)", "st_invalid": "Failed", "st_unknown": "Unknown",
        "targets_count": "Extracted Targets:",
        "time_elapsed": "Elapsed:", "time_eta": "ETA:", "scan_rate": "Rate: {}/s",
        "dlg_custom_title": "Custom Export", "dlg_fmt": "Export Format:", "dlg_status": "Status:", "dlg_cdn": "Provider:", "dlg_btn_export": "Export File",
        "dlg_val_all_suc": "All Successful", "dlg_val_all_cdn": "All Networks", "dlg_val_txt": "Grouped Text (TXT)", "dlg_val_csv": "Excel Sheet (CSV)",
        "upd_avail": "New version ({}) is available.\nOpen download page?", "upd_latest": "You are using the latest version.", "upd_not_found": "No release information found.",
        "lbl_my_isp": "📡 Your Public IP/ISP:", "isp_fetching": "Detecting...",
        "warn_vpn": "⚠️ Non-Iran IP (VPN Active)", "warn_iran": "🇮🇷 Iran Local IP",
        "ctx_copy_ip": "Copy IP Only", "ctx_copy_ipport": "Copy IP:Port", "ctx_copy_detail": "Copy Detailed Info",
        
        "rmgr_title": "CDN Range Manager & Random IP Generator",
        "rmgr_cdn_select": "Select Network / CDN Provider:",
        "rmgr_subnets_label": "CIDR Subnets List (Editable):",
        "rmgr_btn_add": "➕ Add Range",
        "rmgr_btn_reset": "🔄 Reset to CDN Ranges",
        "rmgr_btn_load_subnets": "📥 Load Raw CIDR Subnets to Scanner",
        "rmgr_mode_total": "Generate specified total random IPs (Distributed)",
        "rmgr_mode_per_range": "Generate specified random IPs per subnet",
        "rmgr_count_label": "Random IP Count:",
        "rmgr_btn_generate": "🎲 Generate Random IPs & Transfer to Scanner",
        "rmgr_msg_empty": "No valid CIDR ranges found in list.",
        "rmgr_msg_success": "{} random IPs transferred to main scanner input."
    }
}

# ==============================================================================
# ۴. ماژول‌های کمکی شبکه و ساخت پکت واقعی TLS 1.3 ClientHello
# ==============================================================================
class NetworkInterfaceHelper:
    @staticmethod
    def get_default_interface_ipv4(target_ip="8.8.8.8") -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target_ip, 53))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            s.close()

class ClientHelloMaker:
    tls_ch_template_str = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20"
        "bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030"
        "c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e69"
        "72000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e00"
        "0c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b08"
        "0408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024"
        "001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d500000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000"
    )
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = b"mci.ir"
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"

    @classmethod
    def get_client_hello(cls, target_sni: str) -> bytes:
        target_sni_bytes = target_sni.encode('ascii')
        rnd = os.urandom(32)
        sess_id = os.urandom(32)
        key_share = os.urandom(32)
        server_name_ext = (
            struct.pack("!H", len(target_sni_bytes) + 5) +
            struct.pack("!H", len(target_sni_bytes) + 3) +
            b"\x00" +
            struct.pack("!H", len(target_sni_bytes)) +
            target_sni_bytes
        )
        pad_len = max(0, 219 - len(target_sni_bytes))
        padding_ext = struct.pack("!H", pad_len) + (b"\x00" * pad_len)
        return (
            cls.static1 + rnd + cls.static2 + sess_id + cls.static3 +
            server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext
        )

# ==============================================================================
# ۵. ماژول استخراج هوشمند ورودی‌ها (Smart Target Extractor)
# ==============================================================================
class SmartTargetExtractor:
    IPV4_CIDR_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[12][0-9]|3[0-2])\b')
    IPV6_CIDR_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:?/[0-9]{1,3}\b')
    IPV4_RANGE_PATTERN = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3})\b')
    
    IPV6_WITH_PORT_PATTERN = re.compile(r'\[([0-9a-fA-F:]+)\]:(\d{1,5})')
    IPV6_PLAIN_PATTERN = re.compile(r'(?<![0-9a-fA-F:])([0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:|:)+[0-9a-fA-F]{1,4})(?![0-9a-fA-F:])')
    
    IPV4_PATTERN = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b')
    DOMAIN_PATTERN = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})(?::(\d{1,5}))?\b')

    @classmethod
    def extract(cls, raw_text: str, max_cidr_hosts: int = 256, remove_http: bool = True):
        extracted = []
        working_text = raw_text

        uri_matches = re.findall(r'(?:https?|vless|vmess|trojan|ss|ssr)://([^\s\'"<>]+)', working_text, re.IGNORECASE)
        for uri in uri_matches:
            target_part = uri.split('#')[0].split('?')[0].split('/')[0]
            if '@' in target_part:
                target_part = target_part.split('@')[-1]
            working_text += f" {target_part} "

        for cidr in cls.IPV4_CIDR_PATTERN.findall(working_text):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                count = 0
                for ip in net.hosts():
                    extracted.append({"label": str(ip), "host": str(ip), "port": None, "type": "ipv4"})
                    count += 1
                    if count >= max_cidr_hosts: break
                if count == 0 and net.num_addresses == 1:
                    extracted.append({"label": str(net.network_address), "host": str(net.network_address), "port": None, "type": "ipv4"})
            except ValueError: pass
        working_text = cls.IPV4_CIDR_PATTERN.sub(' ', working_text)

        for cidr in cls.IPV6_CIDR_PATTERN.findall(working_text):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                count = 0
                for ip in net.hosts():
                    extracted.append({"label": str(ip), "host": str(ip), "port": None, "type": "ipv6"})
                    count += 1
                    if count >= max_cidr_hosts: break
                if count == 0 and net.num_addresses == 1:
                    extracted.append({"label": str(net.network_address), "host": str(net.network_address), "port": None, "type": "ipv6"})
            except ValueError: pass
        working_text = cls.IPV6_CIDR_PATTERN.sub(' ', working_text)

        for start_ip, end_ip in cls.IPV4_RANGE_PATTERN.findall(working_text):
            try:
                ip1 = ipaddress.IPv4Address(start_ip)
                ip2 = ipaddress.IPv4Address(end_ip)
                if int(ip1) <= int(ip2):
                    span = min(int(ip2) - int(ip1) + 1, max_cidr_hosts)
                    for i in range(span):
                        curr = str(ipaddress.IPv4Address(int(ip1) + i))
                        extracted.append({"label": curr, "host": curr, "port": None, "type": "ipv4"})
            except ValueError: pass
        working_text = cls.IPV4_RANGE_PATTERN.sub(' ', working_text)

        for ip6, port_str in cls.IPV6_WITH_PORT_PATTERN.findall(working_text):
            try:
                ipaddress.IPv6Address(ip6)
                p = int(port_str) if 0 < int(port_str) <= 65535 else None
                extracted.append({"label": f"[{ip6}]" + (f":{p}" if p else ""), "host": ip6, "port": p, "type": "ipv6"})
            except ValueError: pass
        working_text = cls.IPV6_WITH_PORT_PATTERN.sub(' ', working_text)

        for ip6 in cls.IPV6_PLAIN_PATTERN.findall(working_text):
            try:
                ipaddress.IPv6Address(ip6)
                extracted.append({"label": ip6, "host": ip6, "port": None, "type": "ipv6"})
            except ValueError: pass
        working_text = cls.IPV6_PLAIN_PATTERN.sub(' ', working_text)

        for ip4, port_str in cls.IPV4_PATTERN.findall(working_text):
            try:
                ipaddress.IPv4Address(ip4)
                p = int(port_str) if port_str and 0 < int(port_str) <= 65535 else None
                extracted.append({"label": f"{ip4}" + (f":{p}" if p else ""), "host": ip4, "port": p, "type": "ipv4"})
            except ValueError: pass
        working_text = cls.IPV4_PATTERN.sub(' ', working_text)

        for domain, port_str in cls.DOMAIN_PATTERN.findall(working_text):
            label = domain
            if remove_http and label.lower().startswith("www."):
                label = label[4:]
            p = int(port_str) if port_str and 0 < int(port_str) <= 65535 else None
            extracted.append({"label": f"{label}" + (f":{p}" if p else ""), "host": domain, "port": p, "type": "domain"})

        unique_results = []
        seen = set()
        for item in extracted:
            identity = (item["host"], item["port"])
            if identity not in seen:
                seen.add(identity)
                unique_results.append(item)

        return unique_results

# ==============================================================================
# ۶. ماژول تولید آی‌پی‌های تصادفی (Random IP Generator)
# ==============================================================================
class RandomIPGenerator:
    @staticmethod
    def generate(cidr_list, mode="total", count=50):
        networks = []
        for c in cidr_list:
            c = c.strip()
            if not c: continue
            try:
                net = ipaddress.ip_network(c, strict=False)
                networks.append(net)
            except ValueError: pass

        if not networks: return []

        def get_single_random_ip(net):
            num = net.num_addresses
            if num <= 2: return str(net.network_address)
            max_offset = min(num - 2, (1 << 64) - 1)
            offset = random.randint(1, max_offset)
            return str(ipaddress.ip_address(int(net.network_address) + offset))

        results = []
        if mode == "per_range":
            for net in networks:
                seen = set()
                attempts = 0
                while len(seen) < count and attempts < count * 15:
                    attempts += 1
                    ip_str = get_single_random_ip(net)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        results.append(ip_str)
        else:
            seen = set()
            attempts = 0
            while len(seen) < count and attempts < count * 25:
                attempts += 1
                net = random.choice(networks)
                ip_str = get_single_random_ip(net)
                if ip_str not in seen:
                    seen.add(ip_str)
                    results.append(ip_str)

        return results

# ==============================================================================
# ۷. دیالوگ مدیریت رنج‌های CDN و ساخت آی‌پی تصادفی
# ==============================================================================
class RangeManagerDialog(tk.Toplevel):
    def __init__(self, parent, current_lang, theme_state, on_inject_callback):
        super().__init__(parent)
        self.current_lang = current_lang
        self.theme_state = theme_state
        self.on_inject = on_inject_callback

        t = LANG[self.current_lang]
        self.title(t["rmgr_title"])
        self.geometry("750x620")
        self.minsize(650, 520)
        self.transient(parent)
        self.grab_set()

        self.cdn_map = dict(CDN_RANGES)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        t = LANG[self.current_lang]
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top_frame = ttk.Frame(self, padding=10)
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(1, weight=1)

        ttk.Label(top_frame, text=t["rmgr_cdn_select"], font=("Tahoma", 9, "bold")).grid(row=0, column=0, sticky="w", padx=5)
        
        cdn_names = list(self.cdn_map.keys())
        self.cdn_combo_var = tk.StringVar(value=cdn_names[0])
        self.cdn_combo = ttk.Combobox(top_frame, textvariable=self.cdn_combo_var, values=cdn_names, state="readonly")
        self.cdn_combo.grid(row=0, column=1, sticky="ew", padx=5)
        self.cdn_combo.bind("<<ComboboxSelected>>", self.on_cdn_changed)

        btn_reset = ttk.Button(top_frame, text=t["rmgr_btn_reset"], command=self.reset_current_cdn)
        btn_reset.grid(row=0, column=2, padx=5)

        lbl_info = ttk.Label(self, text=t["rmgr_subnets_label"], font=("Tahoma", 9, "bold"), padding=(10, 5, 10, 0))
        lbl_info.grid(row=1, column=0, sticky="w")

        self.text_ranges = tk.Text(self, font=("Consolas", 10), wrap="none", undo=True)
        self.text_ranges.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.text_ranges.yview)
        self.text_ranges.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=2, column=1, sticky="ns", pady=5)

        action_frame = ttk.LabelFrame(self, text=f" {t['btn_range_mgr']} ", padding=10)
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        action_frame.columnconfigure(1, weight=1)

        self.gen_mode_var = tk.StringVar(value="total")
        
        rb_total = ttk.Radiobutton(action_frame, text=t["rmgr_mode_total"], variable=self.gen_mode_var, value="total")
        rb_total.grid(row=0, column=0, columnspan=2, sticky="w", pady=2)

        rb_per_range = ttk.Radiobutton(action_frame, text=t["rmgr_mode_per_range"], variable=self.gen_mode_var, value="per_range")
        rb_per_range.grid(row=1, column=0, columnspan=2, sticky="w", pady=2)

        count_frame = ttk.Frame(action_frame)
        count_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Label(count_frame, text=t["rmgr_count_label"]).pack(side="left", padx=(0, 5))
        self.count_var = tk.IntVar(value=40)
        spin_count = ttk.Spinbox(count_frame, from_=1, to=10000, textvariable=self.count_var, width=8, justify="center")
        spin_count.pack(side="left")

        btn_bar = ttk.Frame(action_frame)
        btn_bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        btn_bar.columnconfigure(0, weight=1)
        btn_bar.columnconfigure(1, weight=1)

        btn_direct_load = ttk.Button(btn_bar, text=t["rmgr_btn_load_subnets"], command=self.load_subnets_directly)
        btn_direct_load.grid(row=0, column=0, sticky="ew", padx=4)

        btn_gen_ips = ttk.Button(btn_bar, text=t["rmgr_btn_generate"], style="Primary.TButton", command=self.generate_and_inject)
        btn_gen_ips.grid(row=0, column=1, sticky="ew", padx=4)

        self.on_cdn_changed()

    def apply_theme(self):
        bg_col = "#000000" if self.theme_state == 2 else ("#212529" if self.theme_state == 1 else "#f8f9fa")
        fg_col = "#a0a0a0" if self.theme_state == 2 else ("#f8f9fa" if self.theme_state == 1 else "#212529")
        input_bg = "#111111" if self.theme_state == 2 else ("#495057" if self.theme_state == 1 else "white")

        self.configure(bg=bg_col)
        self.text_ranges.configure(bg=input_bg, fg=fg_col, insertbackground=fg_col)

    def on_cdn_changed(self, event=None):
        cdn = self.cdn_combo_var.get()
        subnets = self.cdn_map.get(cdn, [])
        self.text_ranges.delete("1.0", tk.END)
        self.text_ranges.insert("1.0", "\n".join(subnets))

    def reset_current_cdn(self):
        self.on_cdn_changed()

    def get_valid_lines(self):
        raw = self.text_ranges.get("1.0", tk.END).splitlines()
        return [line.strip() for line in raw if line.strip()]

    def load_subnets_directly(self):
        lines = self.get_valid_lines()
        if not lines:
            messagebox.showwarning(LANG[self.current_lang]["msg_warning"], LANG[self.current_lang]["rmgr_msg_empty"], parent=self)
            return
        self.on_inject("\n".join(lines))
        self.destroy()

    def generate_and_inject(self):
        t = LANG[self.current_lang]
        lines = self.get_valid_lines()
        if not lines:
            messagebox.showwarning(t["msg_warning"], t["rmgr_msg_empty"], parent=self)
            return

        mode = self.gen_mode_var.get()
        count = max(1, self.count_var.get())

        generated_ips = RandomIPGenerator.generate(lines, mode=mode, count=count)
        if not generated_ips:
            messagebox.showerror(t["msg_error"], t["rmgr_msg_empty"], parent=self)
            return

        self.on_inject("\n".join(generated_ips))
        messagebox.showinfo(t["msg_success"], t["rmgr_msg_success"].format(len(generated_ips)), parent=self)
        self.destroy()

# ==============================================================================
# ۸. کلاس اصلی نرم‌افزار، موتور اسکنر و ناوبری سراسری
# ==============================================================================
class SNIScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1440x940")
        self.root.minsize(1100, 700)
        
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
        self.setup_context_menu()
        self.bind_global_hotkeys()
        self.apply_language()
        
        threading.Thread(target=self.fetch_public_network_info, daemon=True).start()
        
        self.root.after(100, self.process_queue)
        self.root.after(1000, self.update_timer)

    def fetch_public_network_info(self):
        try:
            local_ip = NetworkInterfaceHelper.get_default_interface_ipv4()
            req = urllib.request.Request("http://ip-api.com/json/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode())
                isp = data.get('isp', '')
                org = data.get('org', '')
                country = data.get('countryCode', '')
                ip = data.get('query', '')
                
                disp_isp = isp if isp else (org if org else "Unknown Network")
                disp = f"{disp_isp} (Pub: {ip} | Loc: {local_ip})"
                
                if country == "IR":
                    warn_text = LANG[self.current_lang]["warn_iran"]
                    warn_color = "#198754" if self.theme_state != 2 else "#34d399"
                else:
                    warn_text = LANG[self.current_lang]["warn_vpn"]
                    warn_color = "#dc3545" if self.theme_state != 2 else "#f87171"
                
                self.root.after(0, lambda: self.lbl_isp_val.configure(text=disp, foreground="#0d6efd" if self.theme_state != 2 else "#38bdf8"))
                self.root.after(0, lambda: self.lbl_isp_warn.configure(text=warn_text, foreground=warn_color))
        except Exception:
            local_ip = NetworkInterfaceHelper.get_default_interface_ipv4()
            self.root.after(0, lambda: self.lbl_isp_val.configure(text=f"Offline / Loc: {local_ip}", foreground="#dc3545"))
            self.root.after(0, lambda: self.lbl_isp_warn.configure(text=""))

    def bind_global_hotkeys(self):
        # هات‌کی‌های سراسری متنی
        for widget in ("Text", "Entry", "TEntry", "Combobox", "TCombobox"):
            self.root.bind_class(widget, "<Control-a>", self.hotkey_select_all)
            self.root.bind_class(widget, "<Control-A>", self.hotkey_select_all)
            self.root.bind_class(widget, "<Control-c>", self.hotkey_copy)
            self.root.bind_class(widget, "<Control-C>", self.hotkey_copy)
            self.root.bind_class(widget, "<Control-v>", self.hotkey_paste)
            self.root.bind_class(widget, "<Control-V>", self.hotkey_paste)
            self.root.bind_class(widget, "<Control-x>", self.hotkey_cut)
            self.root.bind_class(widget, "<Control-X>", self.hotkey_cut)

        # هات‌کی‌های کنترلی سراسری
        self.root.bind("<F5>", lambda e: self.start_scan() if not self.is_scanning else None)
        self.root.bind("<Control-Return>", lambda e: self.start_scan() if not self.is_scanning else None)
        self.root.bind("<Escape>", lambda e: self.stop_scan() if self.is_scanning else None)
        self.root.bind("<Control-s>", lambda e: self.save_settings())
        self.root.bind("<Control-S>", lambda e: self.save_settings())
        self.root.bind("<Control-e>", lambda e: self.export_config())
        self.root.bind("<Control-E>", lambda e: self.export_config())
        self.root.bind("<Control-Shift-E>", lambda e: self.export_csv())
        self.root.bind("<Control-Shift-e>", lambda e: self.export_csv())
        self.root.bind("<Control-r>", lambda e: self.open_range_manager())
        self.root.bind("<Control-R>", lambda e: self.open_range_manager())
        self.root.bind("<Control-d>", lambda e: self.remove_duplicates())
        self.root.bind("<Control-D>", lambda e: self.remove_duplicates())

    def hotkey_select_all(self, event):
        if hasattr(event.widget, "tag_add"):
            event.widget.tag_add("sel", "1.0", "end")
        elif hasattr(event.widget, "select_range"):
            event.widget.select_range(0, 'end')
        return "break"
        
    def hotkey_copy(self, event):
        try:
            if hasattr(event.widget, "tag_ranges") and event.widget.tag_ranges("sel"):
                self.root.clipboard_clear()
                self.root.clipboard_append(event.widget.get("sel.first", "sel.last"))
                return "break"
            elif hasattr(event.widget, "selection_get"):
                self.root.clipboard_clear()
                self.root.clipboard_append(event.widget.selection_get())
                return "break"
        except tk.TclError: pass

    def hotkey_paste(self, event):
        try:
            text = self.root.clipboard_get()
            if hasattr(event.widget, "insert"):
                event.widget.insert("insert", text)
            return "break"
        except tk.TclError: pass

    def hotkey_cut(self, event):
        try:
            if hasattr(event.widget, "tag_ranges") and event.widget.tag_ranges("sel"):
                self.root.clipboard_clear()
                self.root.clipboard_append(event.widget.get("sel.first", "sel.last"))
                event.widget.delete("sel.first", "sel.last")
                return "break"
        except tk.TclError: pass

    def setup_context_menu(self):
        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="Copy IP", command=self.copy_tree_ip)
        self.tree_menu.add_command(label="Copy IP:Port", command=self.copy_tree_ip_port)
        self.tree_menu.add_command(label="Copy Detailed Info", command=self.copy_tree_detailed)
        self.tree.bind("<Button-3>", self.show_tree_menu)

    def show_tree_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def copy_tree_ip(self):
        selected = self.tree.selection()
        if not selected: return
        vals = self.tree.item(selected[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(vals[2])

    def copy_tree_ip_port(self):
        selected = self.tree.selection()
        if not selected: return
        vals = self.tree.item(selected[0], "values")
        ip_val = vals[2]
        if ":" in ip_val and not ip_val.startswith("["):
            ip_val = f"[{ip_val}]"
        self.root.clipboard_clear()
        self.root.clipboard_append(f"{ip_val}:{vals[3]}")

    def copy_tree_detailed(self):
        selected = self.tree.selection()
        if not selected: return
        vals = self.tree.item(selected[0], "values")
        sni = self.tree.item(selected[0], "text")
        detail = f"Target: {vals[1]} | IP: {vals[2]}:{vals[3]} | SNI: {sni} | CDN: {vals[7]} | ICMP: {vals[4]} | TCP: {vals[5]} | Speed: {vals[8]} | Status: {vals[10]}"
        self.root.clipboard_clear()
        self.root.clipboard_append(detail)

    def paste_from_clipboard(self):
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                self.text_input.insert(tk.END, clipboard_text + "\n")
        except tk.TclError:
            messagebox.showwarning(LANG[self.current_lang]["msg_warning"], LANG[self.current_lang]["msg_empty_clipboard"])

    def load_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text/Config Files", "*.txt *.json *.yaml *.yml"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.text_input.insert(tk.END, f.read() + "\n")
            except Exception as e:
                messagebox.showerror(LANG[self.current_lang]["msg_error"], str(e))

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
        header_frame.columnconfigure(3, weight=1)
        
        self.btn_theme = ttk.Button(header_frame, command=self.cycle_theme, width=12)
        self.btn_theme.grid(row=0, column=0, sticky="w", padx=(0, 2))

        self.btn_lang = ttk.Button(header_frame, command=self.toggle_language, width=8)
        self.btn_lang.grid(row=0, column=1, sticky="w", padx=2)
        
        self.lbl_update = tk.Label(header_frame, font=("Tahoma", 8, "underline"), fg="#198754", cursor="hand2")
        self.lbl_update.grid(row=0, column=2, sticky="w", padx=5)
        self.lbl_update.bind("<Button-1>", lambda e: self.check_for_updates())

        self.lbl_tg = tk.Label(header_frame, font=("Tahoma", 8, "underline"), fg="#0d6efd", cursor="hand2")
        self.lbl_tg.grid(row=0, column=3, sticky="w", padx=5)
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
        self.btn_shuffle = ttk.Button(input_tools, command=self.shuffle_inputs)
        self.btn_shuffle.pack(side="left", padx=2)
        self.btn_clear = ttk.Button(input_tools, command=lambda: self.text_input.delete("1.0", tk.END))
        self.btn_clear.pack(side="right", padx=2)
        
        self.btn_range_mgr = ttk.Button(input_tools, style="Primary.TButton", command=self.open_range_manager)
        self.btn_range_mgr.pack(side="right", padx=2)

        self.text_input = tk.Text(self.right_panel, width=40, height=8, font=("Consolas", 10), undo=True)
        self.text_input.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        self.right_panel.rowconfigure(2, weight=1)

        # ====== پنل تنظیمات رادار ======
        self.settings_frame = ttk.LabelFrame(self.right_panel, padding=10)
        self.settings_frame.grid(row=3, column=0, sticky="nsew")
        self.settings_frame.columnconfigure(1, weight=1)

        row_idx = 0
        sni_frame = ttk.Frame(self.settings_frame)
        sni_frame.grid(row=row_idx, column=0, sticky="ew", padx=5, pady=4)
        self.sni_input = tk.Text(sni_frame, height=3, width=25, font=("Consolas", 10), undo=True)
        self.sni_input.insert("1.0", "www.hcaptcha.com")
        self.sni_input.pack(side="left", fill="x", expand=True)
        
        sni_lbl_frame = ttk.Frame(self.settings_frame)
        sni_lbl_frame.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)
        self.lbl_set_sni = ttk.Label(sni_lbl_frame)
        self.lbl_set_sni.pack(side="top", anchor="e")
        self.btn_presets_sni = ttk.Button(sni_lbl_frame, command=self.show_sni_presets)
        self.btn_presets_sni.pack(side="top", anchor="e", pady=2)
        
        row_idx += 1
        ports_frame = ttk.Frame(self.settings_frame)
        ports_frame.grid(row=row_idx, column=0, sticky="ew", padx=5, pady=4)
        self.ports_input = tk.Text(ports_frame, height=2, width=25, font=("Consolas", 10), undo=True)
        self.ports_input.insert("1.0", DEFAULT_PORTS)
        self.ports_input.pack(side="left", fill="x", expand=True)
        self.lbl_set_ports = ttk.Label(self.settings_frame)
        self.lbl_set_ports.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        speed_opts_frame = ttk.Frame(self.settings_frame)
        speed_opts_frame.grid(row=row_idx, column=0, sticky="ew", padx=5, pady=4)
        speed_opts_frame.columnconfigure(0, weight=1)

        self.speed_url_var = tk.StringVar(value="/cdn-cgi/trace")
        preset_urls = [p[0] for p in SPEED_TEST_PRESETS]
        self.speed_combo = ttk.Combobox(speed_opts_frame, textvariable=self.speed_url_var, values=preset_urls, justify="left")
        self.speed_combo.grid(row=0, column=0, sticky="ew")

        self.lbl_set_speed_url = ttk.Label(self.settings_frame)
        self.lbl_set_speed_url.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        self.speed_duration_var = tk.DoubleVar(value=3.0)
        ttk.Entry(self.settings_frame, textvariable=self.speed_duration_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=4)
        self.lbl_set_speed_dur = ttk.Label(self.settings_frame)
        self.lbl_set_speed_dur.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        self.cidr_limit_var = tk.IntVar(value=256)
        ttk.Entry(self.settings_frame, textvariable=self.cidr_limit_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=4)
        self.lbl_set_cidr = ttk.Label(self.settings_frame)
        self.lbl_set_cidr.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        self.threads_var = tk.IntVar(value=30)
        ttk.Entry(self.settings_frame, textvariable=self.threads_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=4)
        self.lbl_set_threads = ttk.Label(self.settings_frame)
        self.lbl_set_threads.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Entry(self.settings_frame, textvariable=self.timeout_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=4)
        self.lbl_set_timeout = ttk.Label(self.settings_frame)
        self.lbl_set_timeout.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

        row_idx += 1
        self.retry_count_var = tk.IntVar(value=2)
        ttk.Entry(self.settings_frame, textvariable=self.retry_count_var, width=10, justify="center").grid(row=row_idx, column=0, sticky="e", padx=5, pady=4)
        self.lbl_set_retry = ttk.Label(self.settings_frame)
        self.lbl_set_retry.grid(row=row_idx, column=1, sticky="e", padx=5, pady=4)

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
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self.chk_auto_scroll = ttk.Checkbutton(self.settings_frame, variable=self.auto_scroll_var)
        self.chk_auto_scroll.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

        row_idx += 1
        self.auto_save_var = tk.BooleanVar(value=False)
        self.chk_auto_save = ttk.Checkbutton(self.settings_frame, variable=self.auto_save_var)
        self.chk_auto_save.grid(row=row_idx, column=0, columnspan=2, sticky="e", pady=2)

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
        self.left_panel.rowconfigure(4, weight=1)

        isp_frame = ttk.Frame(self.left_panel)
        isp_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        self.lbl_isp_title = ttk.Label(isp_frame, font=self.font_bold)
        self.lbl_isp_title.pack(side="left")
        self.lbl_isp_val = ttk.Label(isp_frame, font=("Consolas", 9, "bold"))
        self.lbl_isp_val.pack(side="left", padx=5)
        self.lbl_isp_warn = ttk.Label(isp_frame, font=self.font_bold)
        self.lbl_isp_warn.pack(side="left", padx=10)

        self.dash_frame = tk.Frame(self.left_panel)
        self.dash_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        
        self.stat_frames = []
        self.lbl_stat_total_val, self.lbl_stat_total_title = self.create_metric_card(self.dash_frame, "#e9ecef", "#495057")
        self.lbl_stat_success_val, self.lbl_stat_success_title = self.create_metric_card(self.dash_frame, "#d1e7dd", "#0f5132")
        self.lbl_stat_ping_val, self.lbl_stat_ping_title = self.create_metric_card(self.dash_frame, "#cff4fc", "#055160")
        self.lbl_stat_down_val, self.lbl_stat_down_title = self.create_metric_card(self.dash_frame, "#f8d7da", "#842029")

        progress_frame = ttk.Frame(self.left_panel)
        progress_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        progress_frame.columnconfigure(1, weight=1)

        self.lbl_progress_pct = ttk.Label(progress_frame, text="0%", font=self.font_bold, width=5)
        self.lbl_progress_pct.grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=5)
        self.lbl_time_info = ttk.Label(progress_frame, text="", font=("Consolas", 8))
        self.lbl_time_info.grid(row=0, column=2, sticky="e", padx=(5, 0))

        tools_frame = ttk.Frame(self.left_panel)
        tools_frame.grid(row=3, column=0, sticky="ew", pady=(0, 5))
        
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

        columns = ("select", "target", "ip", "port", "icmp", "tcp_ping", "sni_http", "cdn", "speed", "score", "status")
        self.tree = ttk.Treeview(self.left_panel, columns=columns, show="headings")
        
        self.tree.column("select", width=40, anchor="center")
        self.tree.column("target", width=125, anchor="w")
        self.tree.column("ip", width=135, anchor="center")
        self.tree.column("port", width=55, anchor="center")
        self.tree.column("icmp", width=105, anchor="center") 
        self.tree.column("tcp_ping", width=75, anchor="center")
        self.tree.column("sni_http", width=120, anchor="center")
        self.tree.column("cdn", width=100, anchor="center")
        self.tree.column("speed", width=95, anchor="center")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("status", width=95, anchor="center")

        self.tree.grid(row=4, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(self.left_panel, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=4, column=1, sticky='ns')

        self.tree.bind('<ButtonRelease-1>', self.toggle_check)

        self.lbl_status = ttk.Label(self.left_panel)
        self.lbl_status.grid(row=5, column=0, sticky="e", pady=5)

    def create_metric_card(self, parent, bg_color, fg_color):
        frame = tk.Frame(parent, bg=bg_color, bd=1, relief="ridge")
        frame.pack(side="left", fill="both", expand=True, padx=3)
        self.stat_frames.append(frame)
        lbl_val = tk.Label(frame, text="0", font=("Consolas", 15, "bold"), bg=bg_color, fg=fg_color)
        lbl_val.pack(pady=(8, 0))
        lbl_title = tk.Label(frame, font=("Tahoma", 8, "bold"), bg=bg_color, fg=fg_color)
        lbl_title.pack(pady=(0, 8))
        return lbl_val, lbl_title

    def open_range_manager(self):
        def on_inject(text_to_inject):
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", text_to_inject + "\n")

        RangeManagerDialog(self.root, self.current_lang, self.theme_state, on_inject)

    def apply_language(self):
        t = LANG[self.current_lang]
        self.root.title(t["title"])
        self.lbl_tg.configure(text=t["telegram"])
        self.lbl_update.configure(text=t["update"])
        self.btn_lang.configure(text=t["lang_toggle"])
        self.btn_theme.configure(text=t[f"theme_{self.theme_state}"])
        self.lbl_input_title.configure(text=t["input_label"])
        self.lbl_isp_title.configure(text=t["lbl_my_isp"])
        if not self.lbl_isp_val.cget("text"):
            self.lbl_isp_val.configure(text=t["isp_fetching"])
        
        self.btn_paste.configure(text=t["paste"])
        self.btn_browse.configure(text=t["browse"])
        self.btn_clear.configure(text=t["clear"])
        self.btn_dedup.configure(text=t["dedup"])
        self.btn_shuffle.configure(text=t["shuffle"])
        self.btn_range_mgr.configure(text=t["btn_range_mgr"])
        
        self.settings_frame.configure(text=f" {t['settings']} ")
        self.lbl_set_sni.configure(text=t["default_sni"])
        self.btn_presets_sni.configure(text=t["btn_presets_sni"])
        self.lbl_set_ports.configure(text=t["target_ports"])
        self.lbl_set_speed_url.configure(text=t["speed_url"])
        self.lbl_set_speed_dur.configure(text=t["speed_duration"])
        self.lbl_set_cidr.configure(text=t["max_cidr"])
        self.lbl_set_threads.configure(text=t["threads"])
        self.lbl_set_timeout.configure(text=t["timeout"])
        self.lbl_set_retry.configure(text=t["retry_count"])
        
        self.chk_port_scan.configure(text=t["port_scan_mode"])
        self.chk_rm_http.configure(text=t["rm_http"])
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

        for col, key in [("select", "col_select"), ("target", "col_target"), ("ip", "col_ip"), ("port", "col_port"), 
                         ("icmp", "col_icmp"), ("tcp_ping", "col_tcp"), ("sni_http", "col_sni_http"), ("cdn", "col_cdn"), 
                         ("speed", "col_speed"), ("score", "col_score"), ("status", "col_status")]:
            self.tree.heading(col, text=t[key], command=lambda c=col: self.treeview_sort_column(c, False))
            
        self.tree_menu.entryconfig(0, label=t["ctx_copy_ip"])
        self.tree_menu.entryconfig(1, label=t["ctx_copy_ipport"])
        self.tree_menu.entryconfig(2, label=t["ctx_copy_detail"])

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
        self.style.map('Treeview', background=[('selected', '#2a2a2a' if self.theme_state == 2 else '#0078D7')])
        
        self.text_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)
        self.ports_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)
        self.sni_input.configure(bg=input_bg, fg=fg_color, insertbackground=fg_color)

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
            speed = (self.stat_checked / elapsed) if elapsed > 0 else 0
            remaining_tasks = max(0, self.stat_total_scans - self.stat_checked)
            eta = (remaining_tasks / speed) if speed > 0 else 0

            t = LANG[self.current_lang]
            rate_str = t["scan_rate"].format(round(speed, 1))
            self.lbl_time_info.configure(text=f"{t['time_elapsed']} {self.format_time(elapsed)} | {t['time_eta']} {self.format_time(eta)} | {rate_str}")
            
        self.root.after(1000, self.update_timer)

    def update_metrics_ui(self):
        self.lbl_stat_total_val.configure(text=f"{self.stat_checked} / {self.stat_total_scans}")
        self.lbl_stat_success_val.configure(text=str(self.stat_success))
        self.lbl_stat_ping_val.configure(text=str(self.stat_ping_only))
        self.lbl_stat_down_val.configure(text=str(self.stat_down))
        
        if self.stat_total_scans > 0:
            pct = min(100.0, max(0.0, (self.stat_checked / self.stat_total_scans) * 100))
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
            "snis": self.sni_input.get("1.0", tk.END).strip(),
            "speed_url": self.speed_url_var.get(),
            "speed_duration": self.speed_duration_var.get(),
            "cidr_limit": self.cidr_limit_var.get(),
            "threads": self.threads_var.get(),
            "timeout": self.timeout_var.get(),
            "retry_count": self.retry_count_var.get(),
            "port_scan": self.port_scan_var.get(),
            "remove_http": self.remove_http_var.get(),
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
            self.sni_input.delete("1.0", tk.END)
            self.sni_input.insert("1.0", settings.get("snis", "www.hcaptcha.com"))
            
            self.speed_url_var.set(settings.get("speed_url", "/cdn-cgi/trace"))
            self.speed_duration_var.set(settings.get("speed_duration", 3.0))
            self.cidr_limit_var.set(settings.get("cidr_limit", 256))
            self.threads_var.set(settings.get("threads", 30))
            self.timeout_var.set(settings.get("timeout", 2.0))
            self.retry_count_var.set(settings.get("retry_count", 2))
            self.port_scan_var.set(settings.get("port_scan", False))
            
            self.remove_http_var.set(settings.get("remove_http", False))
            self.smart_ip_var.set(settings.get("smart_ip", True))
            self.strict_ping_var.set(settings.get("strict_ping", False))
            self.auto_scroll_var.set(settings.get("auto_scroll", True))
            self.auto_save_var.set(settings.get("auto_save", False))
            
            self.theme_state = settings.get("theme_state", 0)
            self.current_lang = settings.get("lang", "fa")
        except Exception:
            pass

    def shuffle_inputs(self):
        lines = self.text_input.get("1.0", tk.END).split('\n')
        valid_lines = [l.strip() for l in lines if l.strip()]
        if len(valid_lines) > 1:
            random.shuffle(valid_lines)
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", '\n'.join(valid_lines) + '\n')

    def remove_duplicates(self):
        lines = self.text_input.get("1.0", tk.END).split('\n')
        unique = list(dict.fromkeys(l.strip() for l in lines if l.strip()))
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", '\n'.join(unique) + '\n')

    def show_sni_presets(self):
        menu = Menu(self.root, tearoff=0)
        for key, val in PRESETS_SNI.items():
            menu.add_command(label=key, command=lambda v=val: self.insert_to_text(self.sni_input, v))
        menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def insert_to_text(self, widget, text):
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)

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
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        if col in ("icmp", "tcp_ping", "speed", "port", "score"):
            def extract_number(val):
                # تبدیل MB/s به KB/s در سورتینگ عددی
                val_str = str(val)
                nums = re.findall(r'\d+\.?\d*', val_str)
                if not nums: return 999999.0 if col in ("icmp", "tcp_ping") else 0.0
                num = float(nums[0])
                if "MB/s" in val_str: num *= 1024.0
                return num
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
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_multicast or 
                ip_obj.is_reserved or ip_obj.is_unspecified):
                return False
            return True
        except ValueError:
            return False

    def get_cdn_display_name(self, cdn_key):
        if self.current_lang == "fa":
            return CDN_TRANSLATIONS.get(cdn_key, "نامشخص")
        return cdn_key if cdn_key else "Unknown"

    def detect_cdn(self, ip_str, http_headers=""):
        h = http_headers.lower()
        if "cf-ray" in h or "server: cloudflare" in h: return self.get_cdn_display_name("Cloudflare")
        if "x-amz-cf-id" in h: return self.get_cdn_display_name("CloudFront")
        if "x-fastly-request-id" in h: return self.get_cdn_display_name("Fastly")
        if "server: akamai" in h or "x-true-cache-key" in h: return self.get_cdn_display_name("Akamai")
        
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, name in COMPILED_SUBNETS:
                if ip_obj in net:
                    return self.get_cdn_display_name(name)
        except ValueError:
            pass
        return self.get_cdn_display_name("Unknown")

    def icmp_ping(self, ip, timeout):
        is_v6 = False
        try:
            if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
                is_v6 = True
        except ValueError:
            pass

        sys_plat = platform.system().lower()
        if sys_plat == 'windows':
            param = '-n'
            t_param = '-w'
            t_val = str(int(timeout * 1000))
            cmd = ['ping', param, '1', t_param, t_val]
            if is_v6: cmd.insert(1, '-6')
            cmd.append(ip)
            kwargs = {'creationflags': 0x08000000}
        else:
            param = '-c'
            t_param = '-W'
            t_val = str(max(1, int(timeout)))
            cmd = ['ping', param, '1', t_param, t_val]
            if is_v6: cmd.insert(1, '-6')
            cmd.append(ip)
            kwargs = {}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1, **kwargs)
            if res.returncode == 0:
                match = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)', res.stdout, re.IGNORECASE)
                if match: return True, float(match.group(1))
                return True, 1.0
        except Exception:
            pass
        return False, None

    # ==============================================================================
    # سیستم نمره‌دهی هوشمند چندمعیاره با اولویت حداکثری سرعت واقعی (Speed-Weighted Score)
    # ==============================================================================
    def calculate_score(self, ping, tcp_ms, tls_ok, tcp_ok, speed_kb, jitter, throttled, stability):
        if not tls_ok and not tcp_ok:
            return 0

        score = 0.0

        # ۱. وضعیت اتصال پایه و هندشیک امن (حداکثر ۲۰ امتیاز)
        if tls_ok: score += 20.0
        elif tcp_ok: score += 10.0

        # ۲. سرعت واقعی دانلود به صورت پیوسته و غیرپله‌ای (حداکثر ۴۵ امتیاز اولویت اول)
        # مقیاس پیوسته لگاریتمی تا سقف ۵۰ مگابایت بر ثانیه (51,200 KB/s)
        if speed_kb > 0:
            speed_clamped = max(10.0, min(51200.0, speed_kb))
            # نسبت لگاریتمی پیوسته
            speed_factor = (math.log10(speed_clamped) - 1.0) / (math.log10(51200.0) - 1.0)
            score += max(0.0, min(45.0, speed_factor * 45.0))

        # ۳. تأخیر شبکه (RTT Ping / Latency) (حداکثر ۲۰ امتیاز)
        latency = tcp_ms if tcp_ms is not None else ping
        if latency is not None:
            lat_clamped = max(40.0, min(600.0, latency))
            score += (1.0 - (lat_clamped - 40.0) / 560.0) * 20.0

        # ۴. پایداری بسته و جیتر خط اینترنت (حداکثر ۱۵ امتیاز)
        score += (stability / 100.0) * 10.0
        if jitter is not None:
            jit_clamped = max(2.0, min(100.0, jitter))
            score += (1.0 - (jit_clamped - 2.0) / 98.0) * 5.0
        else:
            score += 3.0

        # جریمه سنگین افت سرعت ناگهانی (Throttling Penalty)
        if throttled:
            score -= 25.0

        # اگر TLS برقرار نشد، سقف نمره به ۳۵ محدود می‌شود
        if not tls_ok and tcp_ok:
            score = min(score, 35.0)

        return min(100, max(0, int(round(score))))

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
                except ValueError: pass
            elif part.isdigit():
                p = int(part)
                if 0 < p <= 65535: ports.append(p)
        return sorted(list(set(ports)))

    def scan_worker(self, task):
        if self.stop_event.is_set(): return
        
        target_label = task["target_label"]
        test_ip = task["ip"]
        sni_to_use = task["sni"]
        port = task["port"]
        timeout_val = self.timeout_var.get()
        strict_ping = self.strict_ping_var.get()
        retry_max = max(1, self.retry_count_var.get())
        speed_max_duration = max(1.0, float(self.speed_duration_var.get()))
        t = LANG[self.current_lang]

        clean_sni = re.sub(r'(?i)^https?://', '', sni_to_use).split('/')[0]

        if test_ip == "-" or not self.is_valid_ip(test_ip):
            self.result_queue.put({
                'target': target_label, 'ip': test_ip, 'port': port, 'icmp': '-', 'tcp_ping': '-',
                'sni_http': '-', 'cdn': '-', 'speed': '-', 'score': 0, 'status': 'DNS Error', 'cat': 'down'
            })
            return

        ping_history = []
        icmp_ok = False
        for _ in range(retry_max):
            if self.stop_event.is_set(): return
            ok, ms = self.icmp_ping(test_ip, timeout_val)
            if ok: 
                icmp_ok = True
                ping_history.append(ms)
            elif retry_max > 1:
                ping_history.append(0)
                
        if strict_ping and not icmp_ok:
            cdn_name = self.detect_cdn(test_ip)
            self.result_queue.put({
                'target': target_label, 'ip': test_ip, 'port': port, 'icmp': t["st_timeout"], 'tcp_ping': '-',
                'sni_http': '-', 'cdn': cdn_name, 'speed': '-', 'score': 0, 'status': t["st_filtered"], 'cat': 'down'
            })
            return
            
        success_pings = [p for p in ping_history if p > 0]
        ping_avg = round(sum(success_pings) / max(1, len(success_pings)), 1) if icmp_ok else None
        
        stability = int((len(success_pings) / retry_max) * 100) if retry_max > 0 else 100
        stab_icon = "🟢" if stability >= 90 else ("🟡" if stability >= 50 else "🔴")
        
        jitter = round(statistics.stdev(success_pings), 1) if len(success_pings) > 1 else None
        stab_str = f" | {stab_icon} {stability}%" if retry_max > 1 else ""
        icmp_display = f"{ping_avg}ms{stab_str}" if icmp_ok else t["st_timeout"]

        tcp_ok = False
        tcp_ms = None
        tls_ok = False
        raw_http_status = "-"
        speed_kb = 0.0
        throttled = False
        raw_headers = ""
        
        try:
            start_tcp = time.perf_counter()
            with socket.create_connection((test_ip, port), timeout=timeout_val) as sock:
                tcp_ms = round((time.perf_counter() - start_tcp) * 1000, 1)
                tcp_ok = True
                
                req_path = self.speed_url_var.get().strip()
                if not req_path.startswith('/'): req_path = '/' + req_path
                
                req_str = f"GET {req_path} HTTP/1.1\r\nHost: {clean_sni}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                
                if port in [443, 8443, 2053, 2083, 2087, 2096]:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try: ctx.set_alpn_protocols(['h2', 'http/1.1'])
                    except Exception: pass
                    
                    try:
                        ssock = ctx.wrap_socket(sock, server_hostname=clean_sni)
                        tls_ok = True
                        target_sock = ssock
                    except Exception:
                        raw_ch = ClientHelloMaker.get_client_hello(clean_sni)
                        sock.sendall(raw_ch)
                        resp_head = sock.recv(5)
                        if resp_head and resp_head[0] == 0x16:
                            tls_ok = True
                        target_sock = None
                else:
                    target_sock = sock

                # تست دانلود و اندازه‌گیری سرعت واقعی با بافر بهینه ۶۴ کیلوبایتی
                if target_sock and (tls_ok or port not in [443, 8443, 2053, 2083, 2087, 2096]):
                    target_sock.settimeout(timeout_val)
                    start_dl = time.perf_counter()
                    target_sock.sendall(req_str.encode())
                    
                    bytes_recv = 0
                    first_chunk = True
                    samples = []
                    last_sample_time = start_dl
                    
                    while True:
                        try:
                            data = target_sock.recv(65536)
                            if not data: break
                        except (socket.timeout, ssl.SSLError):
                            break

                        now = time.perf_counter()
                        
                        if first_chunk:
                            parts = data.split(b'\r\n\r\n', 1)
                            raw_headers = parts[0].decode(errors='ignore')
                            if raw_headers.startswith('HTTP'): 
                                raw_http_status = raw_headers.split(' ', 1)[-1].split('\r')[0]
                            first_chunk = False
                            
                        bytes_recv += len(data)
                        
                        if now - last_sample_time >= 0.3:
                            samples.append(bytes_recv)
                            last_sample_time = now
                            
                        if now - start_dl >= speed_max_duration: break 
                        
                    duration = max(time.perf_counter() - start_dl, 0.001)
                    speed_kb = round((bytes_recv / 1024) / duration, 1)
                    
                    # الگوریتم سنجش افت شدید سرعت جریان (Throttling Detection)
                    if len(samples) >= 3:
                        mid = len(samples) // 2
                        s1 = samples[:mid]
                        s2 = samples[mid:]
                        avg1 = sum(s1) / max(1, len(s1))
                        avg2 = sum(s2) / max(1, len(s2))
                        if avg1 > 0 and (avg1 - avg2) / avg1 > 0.45:
                            throttled = True
        except Exception:
            pass
        
        cdn_name = self.detect_cdn(test_ip, raw_headers)
        score_val = self.calculate_score(ping_avg, tcp_ms, tls_ok, tcp_ok, speed_kb, jitter, throttled, stability)
        
        formatted_http = HTTPStatusFormatter.format_status(raw_http_status, self.current_lang)
        if formatted_http == "-":
            formatted_http = t["st_valid"] if tls_ok else (t["st_invalid"] if tcp_ok else '-')

        if tls_ok: status, cat = t["st_sni_usable"], "success"
        elif tcp_ok: status, cat = t["st_tcp_ok"], "success"
        elif icmp_ok: status, cat = t["st_ping_only"], "ping_only"
        else: status, cat = t["st_down"], "down"
        
        # فرمت‌بندی هوشمند واحد سرعت (MB/s یا KB/s)
        if speed_kb >= 1024.0:
            spd_disp = f"{speed_kb / 1024.0:.2f} MB/s"
        elif speed_kb > 0:
            spd_disp = f"{speed_kb:.1f} KB/s"
        else:
            spd_disp = "-"

        if throttled: spd_disp += " ⚠️"

        self.result_queue.put({
            'target': target_label, 'ip': test_ip, 'port': port, 
            'icmp': icmp_display, 
            'tcp_ping': f"{tcp_ms} ms" if tcp_ok else "-",
            'sni_http': formatted_http, 
            'cdn': cdn_name, 'speed': spd_disp, 
            'score': score_val, 'status': status, 'cat': cat, 'sni_used': clean_sni
        })

    def start_scan(self):
        raw_text = self.text_input.get("1.0", tk.END)
        t = LANG[self.current_lang]
        
        parsed_ports = self.parse_ports_input(self.ports_input.get("1.0", tk.END))
        if not parsed_ports: parsed_ports = [443]
        
        raw_snis = self.sni_input.get("1.0", tk.END).strip().split('\n')
        snis_list = [s.strip() for s in raw_snis if s.strip()]
        if not snis_list: snis_list = ["www.hcaptcha.com"]

        max_cidr = max(1, self.cidr_limit_var.get())
        rm_http = self.remove_http_var.get()
        parsed_targets = SmartTargetExtractor.extract(raw_text, max_cidr_hosts=max_cidr, remove_http=rm_http)

        if not parsed_targets:
            messagebox.showwarning(t["msg_error"], t["msg_no_target"])
            return

        tasks = []
        unique_targets_count = set()
        force_port_scan = self.port_scan_var.get()
        
        for p_target in parsed_targets:
            t_label = p_target["label"]
            host = p_target["host"]
            target_type = p_target["type"]
            specific_port = p_target["port"]
            
            ports_to_scan = parsed_ports if force_port_scan or not specific_port else [specific_port]
            unique_targets_count.add(t_label)

            resolved_ips = []
            if target_type == "domain":
                try:
                    addr_infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                    for item in addr_infos:
                        resolved_ips.append(item[4][0])
                except Exception:
                    if host in FALLBACK_DNS:
                        resolved_ips.extend(FALLBACK_DNS[host])
                resolved_ips = list(dict.fromkeys(resolved_ips))
                if not resolved_ips:
                    resolved_ips = ["-"]
            else:
                resolved_ips = [host]

            for ip_item in resolved_ips:
                if target_type == "domain":
                    for p in ports_to_scan:
                        tasks.append({
                            "target_label": t_label,
                            "ip": ip_item,
                            "sni": host,
                            "port": p
                        })
                else:
                    for sni in snis_list:
                        for p in ports_to_scan:
                            tasks.append({
                                "target_label": t_label,
                                "ip": ip_item,
                                "sni": sni,
                                "port": p
                            })

        for item in self.tree.get_children():
            self.tree.delete(item)

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
            
            score = res['score']
            score_display = f"{score} 🟩" if score > 75 else (f"{score} 🟨" if score > 40 else f"{score} 🟥")
            
            tag = res['cat']
            item_id = self.tree.insert("", tk.END, values=(
                "☐", res['target'], res['ip'], res['port'], res['icmp'], res['tcp_ping'],
                res['sni_http'], res['cdn'], res['speed'], score_display, res['status']
            ), tags=(tag,))
            
            self.tree.item(item_id, text=res.get('sni_used', res['target']))
            
            if self.auto_scroll_var.get():
                self.tree.see(item_id)
            
        self.tree.tag_configure("success", foreground="#198754" if self.theme_state != 2 else "#34d399")
        self.tree.tag_configure("ping_only", foreground="#0d6efd" if self.theme_state != 2 else "#38bdf8")
        self.tree.tag_configure("down", foreground="#dc3545" if self.theme_state != 2 else "#f87171")
        
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
        self.tree.yview_moveto(0) 
        
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
            "FAKE_SNI": self.tree.item(selected_item, "text"),
            "INTERFACE_IPV4": NetworkInterfaceHelper.get_default_interface_ipv4(vals[2]),
            "DATA_MODE": "tls",
            "BYPASS_METHOD": "wrong_seq"
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
        valid_items = []
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
                headers.insert(5, "Used SNI" if self.current_lang == "en" else "SNI استفاده شده")
                writer.writerow(headers)
                writer.writerows(valid_items)
            messagebox.showinfo(t["msg_success"], t["msg_csv_saved"])
        except Exception as e:
            messagebox.showerror(t["msg_error"], str(e))

    def open_custom_export_dialog(self):
        t = LANG[self.current_lang]
        top = tk.Toplevel(self.root)
        top.title(t["dlg_custom_title"])
        top.geometry("450x320")
        top.transient(self.root)
        top.grab_set()
        
        bg_col = "#000" if self.theme_state == 2 else ("#212529" if self.theme_state == 1 else "#f8f9fa")
        fg_col = "#a0a0a0" if self.theme_state == 2 else ("white" if self.theme_state == 1 else "black")
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
        cdn_combo['values'] = (t["dlg_val_all_cdn"], "Cloudflare", "Vercel", "Fastly", "Akamai", "Google Cloud", "Netlify", "CloudFront", "DerakCloud", "IranServer", "ParsPack", "ArvanCloud", t["st_unknown"])
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
                    if cdn_filter not in vals[7] and self.get_cdn_display_name(cdn_filter) not in vals[7]: continue

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
                        headers.insert(5, "Used SNI" if self.current_lang == "en" else "SNI استفاده شده")
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
                                f.write(f"{r['target']}  ->  {r['ip']}:{r['port']}  [Score: {r['score']} | ICMP: {r['icmp']} | Speed: {r['speed']} | CDN: {r['cdn']}]\n")
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
