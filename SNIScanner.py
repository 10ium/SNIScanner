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
from concurrent.futures import ThreadPoolExecutor

class SNIScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("اسکنر و مدیریت پیشرفته SNI")
        self.root.geometry("1100x750")
        
        self.is_dark = False
        
        # فونت‌ها
        self.font_main = ("Tahoma", 10)
        self.font_bold = ("Tahoma", 10, "bold")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.is_scanning = False
        self.executor = None
        self.result_queue = queue.Queue()
        
        self.setup_ui()
        self.apply_theme()
        self.root.after(100, self.process_queue)

    def setup_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        # ====== پنل راست (ورودی و تنظیمات) ======
        self.right_panel = ttk.Frame(self.root)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.right_panel.columnconfigure(0, weight=1)

        # هدر پنل راست (دکمه تم و لیبل)
        header_frame = ttk.Frame(self.right_panel)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header_frame.columnconfigure(0, weight=1)
        
        self.btn_theme = ttk.Button(header_frame, text="🌙 حالت تاریک", command=self.toggle_theme, width=15)
        self.btn_theme.grid(row=0, column=0, sticky="w")
        
        lbl_input = ttk.Label(header_frame, text=":لیست دامنه‌ها و آی‌پی‌ها", font=self.font_bold)
        lbl_input.grid(row=0, column=1, sticky="e")

        self.text_input = tk.Text(self.right_panel, width=40, height=12, font=("Consolas", 10))
        self.text_input.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.right_panel.rowconfigure(1, weight=1)

        # ====== پنل تنظیمات ======
        self.settings_frame = ttk.LabelFrame(self.right_panel, text=" تنظیمات پیشرفته ", padding=10)
        self.settings_frame.grid(row=2, column=0, sticky="nsew")
        self.settings_frame.columnconfigure(1, weight=1)

        # پورت‌ها
        self.ports_var = tk.StringVar(value="443, 2053, 2083, 2087, 2096, 8443")
        ttk.Entry(self.settings_frame, textvariable=self.ports_var, justify="left").grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":پورت‌های هدف (با کاما جدا شوند)").grid(row=0, column=1, sticky="e", padx=5, pady=5)

        # تعداد همزمان
        self.threads_var = tk.IntVar(value=10)
        ttk.Entry(self.settings_frame, textvariable=self.threads_var, width=8, justify="center").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":تعداد بررسی همزمان").grid(row=1, column=1, sticky="e", padx=5, pady=5)

        # زمان انتظار
        self.timeout_var = tk.DoubleVar(value=1.5)
        ttk.Entry(self.settings_frame, textvariable=self.timeout_var, width=8, justify="center").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(self.settings_frame, text=":(Timeout) زمان انتظار (ثانیه)").grid(row=2, column=1, sticky="e", padx=5, pady=5)

        # چک باکس‌ها
        self.remove_http_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="حذف خودکار http:// و https://", variable=self.remove_http_var).grid(row=3, column=0, columnspan=2, sticky="e", pady=2)

        self.remove_www_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="حذف خودکار .www", variable=self.remove_www_var).grid(row=4, column=0, columnspan=2, sticky="e", pady=2)

        self.smart_ip_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="حذف آی‌پی‌های Private/جعل شده", variable=self.smart_ip_var).grid(row=5, column=0, columnspan=2, sticky="e", pady=2)

        self.auto_save_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.settings_frame, text="ذخیره خودکار سریع‌ترین کانفیگ پس از اتمام اسکن", variable=self.auto_save_var).grid(row=6, column=0, columnspan=2, sticky="e", pady=2)

        # دکمه‌های کنترل
        btn_frame = ttk.Frame(self.right_panel)
        btn_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self.btn_start = ttk.Button(btn_frame, text="شروع اسکن", command=self.start_scan)
        self.btn_start.grid(row=0, column=1, sticky="nsew", padx=2)

        self.btn_stop = ttk.Button(btn_frame, text="توقف", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=0, sticky="nsew", padx=2)

        # ====== پنل چپ (نتایج) ======
        self.left_panel = ttk.Frame(self.root)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.left_panel.columnconfigure(0, weight=1)
        self.left_panel.rowconfigure(1, weight=1)

        # ابزارهای بالای جدول
        tools_frame = ttk.Frame(self.left_panel)
        tools_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        self.btn_export = ttk.Button(tools_frame, text="ساخت config.json", style="Success.TButton", command=self.export_config)
        self.btn_export.pack(side="left", padx=2)
        
        self.btn_export_csv = ttk.Button(tools_frame, text="خروجی گروهی (CSV)", command=self.export_csv)
        self.btn_export_csv.pack(side="left", padx=2)
        
        btn_sort = ttk.Button(tools_frame, text="مرتب‌سازی بر اساس سرعت", command=self.sort_results)
        btn_sort.pack(side="left", padx=2)

        self.lbl_results = ttk.Label(tools_frame, text="برای انتخاب خروجی روی باکس خالی در جدول کلیک کنید", font=("Tahoma", 8))
        self.lbl_results.pack(side="right")

        # جدول نتایج
        columns = ("select", "target", "ip", "port", "latency", "speed", "status")
        self.tree = ttk.Treeview(self.left_panel, columns=columns, show="headings")
        
        self.tree.heading("select", text="تیک")
        self.tree.heading("target", text="دامنه / آدرس")
        self.tree.heading("ip", text="آی‌پی")
        self.tree.heading("port", text="پورت")
        self.tree.heading("latency", text="پینگ (ms)")
        self.tree.heading("speed", text="سرعت (KB/s)")
        self.tree.heading("status", text="وضعیت")
        
        self.tree.column("select", width=40, anchor="center")
        self.tree.column("target", width=140, anchor="w")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("latency", width=70, anchor="center")
        self.tree.column("speed", width=85, anchor="center")
        self.tree.column("status", width=80, anchor="center")

        self.tree.grid(row=1, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(self.left_panel, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=1, column=1, sticky='ns')

        self.tree.bind('<ButtonRelease-1>', self.toggle_check)

        self.lbl_status = ttk.Label(self.left_panel, text="آماده به کار...")
        self.lbl_status.grid(row=2, column=0, sticky="e", pady=5)

    def apply_theme(self):
        # تعریف رنگ‌های لایت و دارک
        if self.is_dark:
            bg_color = "#212529"
            fg_color = "#f8f9fa"
            tree_bg = "#343a40"
            tree_fg = "#f8f9fa"
            input_bg = "#495057"
            self.btn_theme.configure(text="☀️ حالت روشن")
            self.lbl_results.configure(foreground="#6ea8fe")
            self.lbl_status.configure(foreground="#adb5bd")
        else:
            bg_color = "#f8f9fa"
            fg_color = "#212529"
            tree_bg = "white"
            tree_fg = "#212529"
            input_bg = "white"
            self.btn_theme.configure(text="🌙 حالت تاریک")
            self.lbl_results.configure(foreground="#0d6efd")
            self.lbl_status.configure(foreground="#6c757d")

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

    def clean_target(self, target):
        target = target.strip()
        target = re.sub(r'^[۰-۹0-9]+\.\s*', '', target)
        if self.remove_http_var.get():
            target = re.sub(r'^https?://', '', target, flags=re.IGNORECASE)
        if self.remove_www_var.get():
            target = re.sub(r'^www\.', '', target, flags=re.IGNORECASE)
        target = target.split('/')[0]
        return target.strip()

    def is_valid_ip(self, ip_str):
        if not self.smart_ip_var.get():
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or not ip_obj.is_global:
                return False
            return True
        except ValueError:
            return False

    def parse_ports(self):
        raw_ports = self.ports_var.get()
        ports =[]
        for p in raw_ports.split(','):
            p = p.strip()
            if p.isdigit() and 0 < int(p) <= 65535:
                ports.append(int(p))
        return ports if ports else [443]

    def measure_speed(self, ip, port, domain, timeout):
        # یک تست سرعت سبک (دریافت هدر و محتوای اولیه سایت)
        try:
            start_time = time.time()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=timeout) as sock:
                # برای پورت‌های رایج HTTPS از SSL استفاده کن
                if port in[443, 8443, 2053, 2083, 2087, 2096]:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        bytes_received = 0
                        while True:
                            data = ssock.recv(4096)
                            if not data: break
                            bytes_received += len(data)
                            if time.time() - start_time > 1.0: # حداکثر 1 ثانیه برای تست دانلود
                                break
                else:
                    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    bytes_received = 0
                    while True:
                        data = sock.recv(4096)
                        if not data: break
                        bytes_received += len(data)
                        if time.time() - start_time > 1.0:
                            break

            duration = time.time() - start_time
            if duration == 0: duration = 0.001
            speed_kbps = (bytes_received / 1024) / duration
            return round(speed_kbps, 1)
        except Exception:
            return 0.0

    def scan_worker(self, target, ports_to_check):
        if not self.is_scanning: return

        try:
            try:
                ipaddress.ip_address(target)
                ips = [target]
            except ValueError:
                _, _, ips = socket.gethostbyname_ex(target)
            
            valid_ips =[ip for ip in ips if self.is_valid_ip(ip)]
            
            if not valid_ips:
                self.result_queue.put({'select': '☐', 'target': target, 'ip': '-', 'port': '-', 'latency': '-', 'speed': '-', 'status': 'Invalid/Private IP'})
                return

            timeout_val = self.timeout_var.get()
            success_found = False

            for ip in set(valid_ips):
                for port in ports_to_check:
                    if not self.is_scanning: return
                    
                    start_time = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout_val)
                    try:
                        # 1. سنجش پینگ
                        sock.connect((ip, port))
                        latency = int((time.time() - start_time) * 1000)
                        sock.close()
                        
                        # 2. سنجش سرعت
                        speed = self.measure_speed(ip, port, target, timeout_val)
                        
                        self.result_queue.put({
                            'select': '☐', 'target': target, 'ip': ip, 'port': port, 'latency': latency, 'speed': speed, 'status': '✔ باز'
                        })
                        success_found = True
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        pass
                    finally:
                        sock.close()
            
            if not success_found:
                self.result_queue.put({'select': '☐', 'target': target, 'ip': valid_ips[0], 'port': 'All', 'latency': '-', 'speed': '-', 'status': '✖ بسته'})

        except socket.gaierror:
            self.result_queue.put({'select': '☐', 'target': target, 'ip': '-', 'port': '-', 'latency': '-', 'speed': '-', 'status': 'DNS Error'})
        except Exception as e:
            self.result_queue.put({'select': '☐', 'target': target, 'ip': '-', 'port': '-', 'latency': '-', 'speed': '-', 'status': 'Error'})

    def start_scan(self):
        raw_targets = self.text_input.get("1.0", tk.END).strip().split('\n')
        targets =[]
        for t in raw_targets:
            cleaned = self.clean_target(t)
            if cleaned and cleaned not in targets:
                targets.append(cleaned)

        if not targets:
            messagebox.showwarning("خطا", "لطفاً حداقل یک دامنه یا آی‌پی وارد کنید.")
            return

        ports_to_check = self.parse_ports()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.is_scanning = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self.btn_export_csv.configure(state="disabled")
        self.lbl_status.configure(text=f"در حال اسکن {len(targets)} هدف روی {len(ports_to_check)} پورت...")

        threads = self.threads_var.get()
        if threads < 1: threads = 1
        
        self.executor = ThreadPoolExecutor(max_workers=threads)
        
        def background_submit():
            for target in targets:
                if not self.is_scanning: break
                self.executor.submit(self.scan_worker, target, ports_to_check)
            self.executor.shutdown(wait=True)
            self.is_scanning = False
            self.root.after(0, self.finish_scan)

        threading.Thread(target=background_submit, daemon=True).start()

    def process_queue(self):
        while not self.result_queue.empty():
            res = self.result_queue.get()
            
            tag = "normal"
            if '✔' in str(res['status']): tag = "success"
            elif '✖' in str(res['status']): tag = "fail"
            elif 'Error' in str(res['status']) or 'Invalid' in str(res['status']): tag = "error"
            
            self.tree.insert("", tk.END, values=(
                res['select'], res['target'], res['ip'], res['port'], res['latency'], res['speed'], res['status']
            ), tags=(tag,))
            
        self.tree.tag_configure("success", foreground="#198754")
        self.tree.tag_configure("fail", foreground="#dc3545")
        self.tree.tag_configure("error", foreground="#6c757d")
        
        self.root.after(100, self.process_queue)

    def stop_scan(self):
        self.is_scanning = False
        self.lbl_status.configure(text="در حال توقف اسکن...")

    def finish_scan(self):
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_export.configure(state="normal")
        self.btn_export_csv.configure(state="normal")
        self.lbl_status.configure(text="اسکن پایان یافت.")
        
        # لاجیک انتخاب و ذخیره خودکار
        if self.auto_save_var.get():
            self.sort_results()
            for child in self.tree.get_children():
                vals = self.tree.item(child, "values")
                if "✔" in vals[6]: # وضعیت موفق
                    self._check_item(child) # تیک زدن خودکار
                    self.export_config(auto=True)
                    break
        else:
            messagebox.showinfo("پایان", "عملیات اسکن با موفقیت به پایان رسید.")

    def sort_results(self):
        items =[(self.tree.set(k, "latency"), self.tree.set(k, "speed"), k) for k in self.tree.get_children("")]
        
        def sort_key(t):
            lat = int(t[0]) if str(t[0]).isdigit() else 999999
            spd = float(t[1]) if str(t[1]).replace('.','',1).isdigit() else 0.0
            # اولویت اول: کمترین پینگ، اولویت دوم: بیشترین سرعت (با منفی کردن سرعت)
            return (lat, -spd)

        items.sort(key=sort_key)
        
        for index, (_, _, k) in enumerate(items):
            self.tree.move(k, '', index)
        
        self.lbl_status.configure(text="نتایج بر اساس کمترین پینگ و بیشترین سرعت مرتب شدند.")

    def export_config(self, auto=False):
        selected_values = None
        for child in self.tree.get_children():
            vals = self.tree.item(child, "values")
            if vals[0] == "☑":
                selected_values = vals
                break
                
        if not selected_values:
            if not auto:
                messagebox.showwarning("خطا", "هیچ موردی انتخاب نشده است.\nلطفاً روی ستون 'تیک' در کنار نتیجه مورد نظر خود کلیک کنید (☑).")
            return

        if "✔" not in selected_values[6]:
            if not auto: messagebox.showwarning("خطا", "ردیفی که تیک زده‌اید پورت باز ندارد.")
            return

        target_domain = selected_values[1]
        ip = selected_values[2]
        port = int(selected_values[3])

        config_data = {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": ip,
            "CONNECT_PORT": port,
            "FAKE_SNI": target_domain
        }

        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            if not auto:
                messagebox.showinfo("موفقیت", "فایل config.json با موفقیت ساخته و ذخیره شد.\n\nمسیر: " + os.path.abspath("config.json"))
            else:
                self.lbl_status.configure(text="بهترین سرور به‌طور خودکار انتخاب و ذخیره شد.")
        except Exception as e:
            if not auto: messagebox.showerror("خطا", f"خطا در ساخت فایل: {str(e)}")

    def export_csv(self):
        # خروجی گرفتن از تمام موارد موفق
        valid_items =[]
        for child in self.tree.get_children():
            vals = self.tree.item(child, "values")
            if "✔" in vals[6]:
                valid_items.append([vals[1], vals[2], vals[3], vals[4], vals[5]])

        if not valid_items:
            messagebox.showwarning("خطا", "هیچ نتیجه موفقی برای خروجی گرفتن وجود ندارد.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv", 
            filetypes=[("CSV Files", "*.csv")],
            title="ذخیره نتایج موفق به صورت CSV",
            initialfile="clean_ips_export.csv"
        )
        
        if not file_path: return

        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Target Domain", "Clean IP", "Port", "Latency (ms)", "Download Speed (KB/s)"])
                writer.writerows(valid_items)
            messagebox.showinfo("موفقیت", f"نتایج موفق با موفقیت در فایل زیر ذخیره شدند:\n{file_path}")
        except Exception as e:
            messagebox.showerror("خطا", f"خطا در ذخیره فایل CSV: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SNIScannerApp(root)
    root.mainloop()
