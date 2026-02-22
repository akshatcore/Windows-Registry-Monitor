import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import winreg
import threading
import time
import json
import os
import math
from datetime import datetime
from fpdf import FPDF

# --- UI Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BASELINE_FILE = "registry_baseline.json"
REPORT_PDF_FILE = "Performa_Security_Report.pdf"
POLL_INTERVAL = 5 

# --- Custom UI Widgets ---
class CircularGauge(tk.Canvas):
    """Responsive circular gauge widget for dashboard metrics."""
    def __init__(self, parent, color, max_value=100, **kwargs):
        bg_color = parent._apply_appearance_mode(parent.cget("fg_color"))
        super().__init__(parent, bg=bg_color, highlightthickness=0, width=0, height=0, **kwargs)
        self.color = color
        self.max_value = max_value
        self.current_value = 0
        self.target_value = 0
        self.bind("<Configure>", self.draw_gauge)

    def set_value(self, value):
        self.target_value = value
        self.animate()

    def animate(self):
        """Smoothly interpolates the current value to the target value."""
        if abs(self.current_value - self.target_value) < 0.1:
            self.current_value = self.target_value
            self.draw_gauge(None)
            return

        self.current_value += (self.target_value - self.current_value) * 0.15
        self.draw_gauge(None)
        self.after(20, self.animate)

    def draw_gauge(self, event):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 10 or h <= 10: return 
        
        size = min(w, h)
        line_width = max(4, int(size / 12)) 
        font_size = max(12, int(size / 4.5))
        
        x_offset = (w - size) / 2
        y_offset = (h - size) / 2
        margin = line_width + 5
        bbox = (x_offset + margin, y_offset + margin, w - x_offset - margin, h - y_offset - margin)
        
        # Background track
        self.create_arc(bbox, start=0, extent=359.9, outline="#333333", width=line_width, style="arc")
        
        extent = (self.current_value / max(1, self.max_value)) * 359.9
        extent = min(359.9, max(0, extent))
        
        # Foreground track 
        if extent > 0:
            self.create_arc(bbox, start=90, extent=-extent, outline=self.color, width=line_width, style="arc")
            
        self.create_text(w/2, h/2, text=str(int(self.target_value)), fill="white", font=("Segoe UI", font_size, "bold"))


class RegistryMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Performa - Registry Monitoring System")
        self.geometry("1150x750")
        self.minsize(950, 600) 
        
        # Internal map for translating winreg ints to readable strings for terminal
        self.hive_names = {
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT"
        }
        
        self.target_keys = [
            {"hive": winreg.HKEY_LOCAL_MACHINE, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name": "HKLM Autorun"},
            {"hive": winreg.HKEY_LOCAL_MACHINE, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "name": "HKLM Autorun (RunOnce)"},
            {"hive": winreg.HKEY_CURRENT_USER, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name": "HKCU Autorun"},
            {"hive": winreg.HKEY_CURRENT_USER, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "name": "HKCU Autorun (RunOnce)"},
            {"hive": winreg.HKEY_LOCAL_MACHINE, "path": r"SOFTWARE\Policies\Microsoft\Windows Defender", "name": "Windows Defender Policies"}
        ]
        
        self.is_monitoring = False
        self.baseline_data = {}
        self.monitor_thread = None
        self.session_logs = []
        self.critical_incidents = []
        self.alert_count = 0
        self.critical_count = 0

        self.setup_ui()
        self.log_message("System Initialized. Awaiting user action.")
        
        # Initialize gauges
        self.gauge_targets.set_value(len(self.target_keys))
        
        if os.path.exists(BASELINE_FILE):
            self.log_message(f"Found existing baseline: {BASELINE_FILE}.")
            self.load_baseline()
            self.btn_start.configure(state="normal")

    def setup_ui(self):
        """Initializes application layout and widgets."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- Sidebar Navigation ---
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(9, weight=1) 

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ Performa Sec", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 40))

        # Professional Button Styles
        primary_style = {"fg_color": "#1f538d", "hover_color": "#14375e", "text_color": "white"}
        secondary_style = {"fg_color": "#2b2b2b", "hover_color": "#3b3b3b", "border_width": 1, "border_color": "#444444", "text_color": "#e0e0e0"}
        start_style = {"fg_color": "#215f3d", "hover_color": "#18452c", "text_color": "white"}
        stop_style = {"fg_color": "#7a2727", "hover_color": "#571c1c", "text_color": "white"}

        # Buttons Group 1: Baseline
        self.btn_baseline = ctk.CTkButton(self.sidebar_frame, text="Create Baseline", command=self.animated_create_baseline, height=35, **primary_style)
        self.btn_baseline.grid(row=1, column=0, padx=20, pady=(10, 5))
        
        self.btn_clear_base = ctk.CTkButton(self.sidebar_frame, text="Clear Baseline", command=self.clear_baseline, height=35, **secondary_style)
        self.btn_clear_base.grid(row=2, column=0, padx=20, pady=(0, 15))

        # Buttons Group 2: Monitoring
        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="Start Monitoring", command=self.start_monitoring, state="disabled", height=35, **start_style)
        self.btn_start.grid(row=3, column=0, padx=20, pady=(10, 5))

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled", height=35, **stop_style)
        self.btn_stop.grid(row=4, column=0, padx=20, pady=(0, 15))

        # Buttons Group 3: Configuration
        self.btn_add_key = ctk.CTkButton(self.sidebar_frame, text="Add Custom Key", command=self.open_add_key_dialog, height=35, **secondary_style)
        self.btn_add_key.grid(row=5, column=0, padx=20, pady=10)

        # Buttons Group 4: Reporting & Logging
        self.btn_report = ctk.CTkButton(self.sidebar_frame, text="Generate Report", command=self.generate_report, height=35, **primary_style)
        self.btn_report.grid(row=6, column=0, padx=20, pady=(15, 5))

        self.btn_open_pdf = ctk.CTkButton(self.sidebar_frame, text="Open PDF", command=self.open_pdf, height=35, **secondary_style)
        self.btn_open_pdf.grid(row=7, column=0, padx=20, pady=(0, 15))

        self.btn_clear_term = ctk.CTkButton(self.sidebar_frame, text="Clear Terminal", command=self.clear_terminal, height=35, **secondary_style)
        self.btn_clear_term.grid(row=8, column=0, padx=20, pady=(15, 10))

        # Buttons Group 5: Info 
        self.btn_info = ctk.CTkButton(self.sidebar_frame, text="About Project", command=self.show_info, height=35, **secondary_style)
        self.btn_info.grid(row=10, column=0, padx=20, pady=(10, 20), sticky="s")

        # --- Main View Area ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="cards")

        # Dashboard metrics cards
        self.card_status = ctk.CTkFrame(self.main_frame, corner_radius=15)
        self.card_status.grid(row=0, column=0, padx=10, pady=(0, 20), sticky="nsew")
        ctk.CTkLabel(self.card_status, text="System Status", font=ctk.CTkFont(weight="bold")).pack(pady=(15, 5))
        
        status_container = ctk.CTkFrame(self.card_status, fg_color="transparent")
        status_container.pack(expand=True, fill="both")
        self.lbl_status = ctk.CTkLabel(status_container, text="OFFLINE", font=ctk.CTkFont(size=22, weight="bold"), text_color="#aaaaaa")
        self.lbl_status.place(relx=0.5, rely=0.5, anchor="center")

        self.card_targets = ctk.CTkFrame(self.main_frame, corner_radius=15)
        self.card_targets.grid(row=0, column=1, padx=10, pady=(0, 20), sticky="nsew")
        ctk.CTkLabel(self.card_targets, text="Monitored Keys", font=ctk.CTkFont(weight="bold")).pack(pady=(15, 0))
        self.gauge_targets = CircularGauge(self.card_targets, color="#4da6ff", max_value=100) 
        self.gauge_targets.pack(expand=True, fill="both", padx=10, pady=10)

        self.card_alerts = ctk.CTkFrame(self.main_frame, corner_radius=15)
        self.card_alerts.grid(row=0, column=2, padx=10, pady=(0, 20), sticky="nsew")
        ctk.CTkLabel(self.card_alerts, text="Total Alerts", font=ctk.CTkFont(weight="bold")).pack(pady=(15, 0))
        self.gauge_alerts = CircularGauge(self.card_alerts, color="#ffb84d", max_value=100) 
        self.gauge_alerts.pack(expand=True, fill="both", padx=10, pady=10)

        self.card_critical = ctk.CTkFrame(self.main_frame, corner_radius=15)
        self.card_critical.grid(row=0, column=3, padx=10, pady=(0, 20), sticky="nsew")
        ctk.CTkLabel(self.card_critical, text="Critical Threats", font=ctk.CTkFont(weight="bold")).pack(pady=(15, 0))
        self.gauge_critical = CircularGauge(self.card_critical, color="#ff4d4d", max_value=100) 
        self.gauge_critical.pack(expand=True, fill="both", padx=10, pady=10)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.main_frame, height=8, corner_radius=5)
        self.progress_bar.grid(row=1, column=0, columnspan=4, sticky="ew", padx=10, pady=(0, 10))
        self.progress_bar.set(0)

        # Console log
        self.log_area = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=13), corner_radius=10)
        self.log_area.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=10, pady=(0, 10))
        
        self.log_area.tag_config("alert", foreground="#ff6b6b")
        self.log_area.tag_config("critical", foreground="#ffffff", background="#cc0000")
        self.log_area.tag_config("success", foreground="#51cf66")


    # --- New UI Actions ---
    def clear_baseline(self):
        """Deletes the current baseline file, resets memory state, and clears dashboard stats."""
        if os.path.exists(BASELINE_FILE):
            try:
                os.remove(BASELINE_FILE)
            except Exception as e:
                self.log_message(f"ERROR: Could not delete baseline file. {str(e)}", alert=True)
                return
                
        self.baseline_data = {}
        self.session_logs = []
        self.critical_incidents = []
        self.alert_count = 0
        self.critical_count = 0
        
        self.gauge_targets.set_value(0)
        self.update_stats() 
        self.btn_start.configure(state="disabled")
        self.clear_terminal() 
        self.log_message("Action: Baseline cleared. System and statistics reset. Create a new baseline to monitor.", success=True)

    def open_pdf(self):
        if os.path.exists(REPORT_PDF_FILE):
            self.log_message(f"Action: Opening {REPORT_PDF_FILE} in default viewer...")
            try:
                os.startfile(REPORT_PDF_FILE)
            except Exception as e:
                self.log_message(f"ERROR: Unable to open PDF. {str(e)}", alert=True)
        else:
            self.log_message("ERROR: No PDF report found. Please generate one first.", alert=True)
            messagebox.showwarning("Report Not Found", "No PDF report exists yet. Please click 'Generate Report' first.")

    def clear_terminal(self):
        self.log_area.configure(state="normal")
        self.log_area.delete("1.0", "end")
        self.log_area.configure(state="disabled")
        self.log_message("Terminal output cleared.", success=True)

    def show_info(self):
        info_text = (
            "Windows Registry Change Monitoring System\n\n"
            "Developed by: Akshat Tiwari\n"
            "GitHub: https://github.com/akshatcore/Windows-Registry-Monitor\n\n"
            "A Blue Team toolkit designed to track unauthorized changes to the "
            "Windows Registry and detect malware persistence."
        )
        messagebox.showinfo("About Project", info_text)


    # --- Existing UI Actions ---
    def animated_create_baseline(self):
        self.btn_baseline.configure(state="disabled")
        self.btn_clear_base.configure(state="disabled")
        self.btn_start.configure(state="disabled")
        self.log_message("Action: Scanning registry and creating Baseline Snapshot...")
        threading.Thread(target=self._baseline_worker, daemon=True).start()

    def _baseline_worker(self):
        self.baseline_data = {}
        total = len(self.target_keys)
        
        for index, target in enumerate(self.target_keys):
            time.sleep(0.15) 
            extracted_values = self.read_registry_key(target['hive'], target['path'])
            # Storing full absolute context for explicit reporting
            self.baseline_data[target['name']] = {"hive": target['hive'], "path": target['path'], "values": extracted_values}
            
            progress = (index + 1) / total
            self.after(0, self.progress_bar.set, progress)

        try:
            with open(BASELINE_FILE, 'w') as f:
                json.dump(self.baseline_data, f, indent=4)
            self.after(0, lambda: self.log_message(f"SUCCESS: Baseline captured and saved to '{BASELINE_FILE}'.", success=True))
            self.after(0, lambda: self.btn_start.configure(state="normal"))
            self.after(0, lambda: self.gauge_targets.set_value(len(self.baseline_data)))
        except Exception as e:
            self.after(0, lambda: self.log_message(f"ERROR: Failed to save baseline: {str(e)}", alert=True))
            
        self.after(0, lambda: self.btn_baseline.configure(state="normal"))
        self.after(0, lambda: self.btn_clear_base.configure(state="normal"))
        self.after(1000, lambda: self.progress_bar.set(0)) 

    def open_add_key_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add Custom Registry Key")
        dialog.geometry("450x380")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Select Registry Hive:", font=ctk.CTkFont(weight="bold")).pack(pady=(20, 5))
        hive_var = ctk.StringVar(value="HKEY_LOCAL_MACHINE")
        ctk.CTkOptionMenu(dialog, variable=hive_var, values=["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_USERS", "HKEY_CLASSES_ROOT"]).pack(pady=(0, 15))

        ctk.CTkLabel(dialog, text="Registry Path:", font=ctk.CTkFont(weight="bold")).pack(pady=(5, 5))
        path_entry = ctk.CTkEntry(dialog, width=350, placeholder_text=r"SOFTWARE\Your\Custom\Path")
        path_entry.pack(pady=(0, 15))

        ctk.CTkLabel(dialog, text="Display Name for Dashboard:", font=ctk.CTkFont(weight="bold")).pack(pady=(5, 5))
        name_entry = ctk.CTkEntry(dialog, width=350, placeholder_text="My Custom App Monitor")
        name_entry.pack(pady=(0, 20))

        def save_custom_key():
            hive_str, path_val, name_val = hive_var.get(), path_entry.get().strip(), name_entry.get().strip()
            if not path_val or not name_val:
                messagebox.showerror("Error", "Path and Name cannot be empty.", parent=dialog)
                return

            hive_map = {"HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE, "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER, "HKEY_USERS": winreg.HKEY_USERS, "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT}
            self.target_keys.append({"hive": hive_map[hive_str], "path": path_val, "name": name_val})

            self.log_message(f"Added custom monitoring target: '{name_val}'", success=True)
            self.log_message("WARNING: You MUST click 'Create Baseline' again to index this new key!", alert=True)
            self.btn_start.configure(state="disabled")
            dialog.destroy()

        ctk.CTkButton(dialog, text="Add to Target List", command=save_custom_key, fg_color="#1f538d", hover_color="#14375e").pack()

    def update_stats(self):
        self.gauge_alerts.set_value(self.alert_count)
        self.gauge_critical.set_value(self.critical_count)

    def log_message(self, message, alert=False, critical=False, success=False):
        self.log_area.configure(state="normal")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.session_logs.append(log_entry)
        
        if critical:
            self.log_area.insert("end", f"[{timestamp}] [CRITICAL] {message}\n", "critical")
            self.critical_incidents.append(log_entry)
            self.critical_count += 1
        elif alert:
            self.log_area.insert("end", f"[{timestamp}] [ALERT] {message}\n", "alert")
            self.alert_count += 1
        elif success:
            self.log_area.insert("end", f"{log_entry}\n", "success")
        else:
            self.log_area.insert("end", f"{log_entry}\n")
            
        self.log_area.see("end") 
        self.log_area.configure(state="disabled")
        self.update_stats()


    # --- Monitoring Logic ---
    def read_registry_key(self, hive, path):
        values_dict = {}
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            num_values = winreg.QueryInfoKey(key)[1]
            for i in range(num_values):
                name, value, reg_type = winreg.EnumValue(key, i)
                if isinstance(value, bytes): value = value.hex()
                name_key = name if name else "(Default)"
                values_dict[name_key] = {"value": value, "type": reg_type}
            winreg.CloseKey(key)
        except FileNotFoundError: pass 
        except PermissionError: self.log_message(f"WARNING: Permission denied reading {path}.", alert=True)
        except Exception as e: self.log_message(f"Error reading {path}: {str(e)}", alert=True)
        return values_dict

    def load_baseline(self):
        try:
            with open(BASELINE_FILE, 'r') as f: self.baseline_data = json.load(f)
            self.log_message("Baseline loaded successfully.", success=True)
            self.gauge_targets.set_value(len(self.baseline_data))
        except Exception as e:
            self.log_message(f"ERROR: Failed to load baseline: {str(e)}", alert=True)

    def start_monitoring(self):
        if not self.baseline_data: return
        self.is_monitoring = True
        self.lbl_status.configure(text="MONITORING", text_color="#51cf66")
        
        self.btn_baseline.configure(state="disabled")
        self.btn_clear_base.configure(state="disabled")
        self.btn_add_key.configure(state="disabled")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        
        self.log_message("Monitoring Started.")
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.is_monitoring = False
        self.lbl_status.configure(text="OFFLINE", text_color="#aaaaaa")
        
        self.btn_baseline.configure(state="normal")
        self.btn_clear_base.configure(state="normal")
        self.btn_add_key.configure(state="normal")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        
        self.log_message("Monitoring Stopped.")

    def monitor_loop(self):
        while self.is_monitoring:
            for target in self.target_keys:
                target_name = target['name']
                current_values = self.read_registry_key(target['hive'], target['path'])
                if target_name in self.baseline_data:
                    self.compare_registry_state(target_name, self.baseline_data[target_name]['values'], current_values)
            time.sleep(POLL_INTERVAL)

    def analyze_suspicious_behavior(self, target_name, action, key_name, value, abs_path):
        is_suspicious = False
        reasons = []
        val_str = str(value).lower()
        if "Autorun" in target_name and action in ["ADDED", "MODIFIED"]:
            if any(ext in val_str for ext in ['.exe', '.bat', '.ps1', '.vbs', '.cmd', '.dll']):
                is_suspicious, reasons = True, reasons + ["Executable/Script added to startup"]
            if any(dir_name in val_str for dir_name in ['appdata', 'temp', 'programdata', 'public']):
                is_suspicious, reasons = True, reasons + ["Executes from hidden/temp directory"]
        if "Defender" in target_name and action in ["ADDED", "MODIFIED"] and "disable" in str(key_name).lower() and str(value) == "1":
            is_suspicious, reasons = True, reasons + ["Attempt to disable Windows Security"]
        
        if is_suspicious:
            self.log_message(f"MALWARE PATTERN DETECTED: [{' | '.join(reasons)}]", critical=True)
            self.log_message(f"  -> Path: {abs_path}\\{key_name}", critical=True)
            self.log_message(f"  -> Payload: '{value}'", critical=True)

    def compare_registry_state(self, target_name, baseline_values, current_values):
        # Extract full context for advanced reporting
        hive_id = self.baseline_data[target_name].get('hive', None)
        base_path = self.baseline_data[target_name].get('path', 'Unknown_Path')
        hive_str = self.hive_names.get(hive_id, "CUSTOM_HIVE")
        abs_path = f"{hive_str}\\{base_path}"

        for key_name, current_data in current_values.items():
            if key_name not in baseline_values:
                self.log_message(f"ENTRY ADDED: {abs_path} -> '{key_name}' = '{current_data['value']}'", alert=True)
                self.analyze_suspicious_behavior(target_name, "ADDED", key_name, current_data['value'], abs_path)
                baseline_values[key_name] = current_data 
                
        keys_to_remove = [k for k in baseline_values.keys() if k not in current_values]
        for key in keys_to_remove:
            self.log_message(f"ENTRY DELETED: {abs_path}\\{key} was removed.", alert=True)
            del baseline_values[key]
            
        for key_name, baseline_data in baseline_values.items():
            if key_name in current_values:
                current_data = current_values[key_name]
                if str(baseline_data['value']) != str(current_data['value']):
                    self.log_message(f"VALUE MODIFIED: {abs_path}\\{key_name} changed from '{baseline_data['value']}' to '{current_data['value']}'", alert=True)
                    self.analyze_suspicious_behavior(target_name, "MODIFIED", key_name, current_data['value'], abs_path)
                    baseline_values[key_name] = current_data

    def generate_report(self):
        self.log_message("Action: Generating Professional Security Report (PDF)...")
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # --- Document Header ---
            pdf.set_font("Arial", 'B', 18)
            pdf.set_text_color(33, 37, 41) 
            pdf.cell(0, 10, "Performa Sec - Registry Monitoring Report", ln=True, align="C")
            pdf.set_font("Arial", 'I', 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 6, "Automated Security & Integrity Scan", ln=True, align="C")
            pdf.ln(10)

            # --- Section: Executive Summary ---
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(31, 83, 141) 
            pdf.cell(0, 8, " 1. Executive Summary ", ln=True, fill=True)
            
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            pdf.cell(0, 6, f"Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.cell(0, 6, f"Total Paths Monitored: {len(self.target_keys)}", ln=True)
            pdf.cell(0, 6, f"Standard Alerts Triggered: {self.alert_count}", ln=True)
            
            pdf.cell(40, 6, "Critical Threats Found: ")
            if self.critical_count > 0:
                pdf.set_text_color(220, 53, 69) 
                pdf.set_font("Arial", 'B', 10)
            pdf.cell(0, 6, str(self.critical_count), ln=True)
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(8)

            # --- Section: Monitored Registry Paths ---
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(31, 83, 141)
            pdf.cell(0, 8, " 2. Monitored Registry Paths (Scope) ", ln=True, fill=True)
            
            pdf.set_font("Arial", '', 9)
            pdf.set_text_color(50, 50, 50)
            pdf.ln(2)
            
            hive_map = {winreg.HKEY_LOCAL_MACHINE: "HKLM", winreg.HKEY_CURRENT_USER: "HKCU"}
            
            for target in self.target_keys:
                hive_name = hive_map.get(target['hive'], "CUSTOM_HIVE")
                pdf.multi_cell(0, 6, f"[{hive_name}] {target['name']}:\n  -> {target['path']}")
                pdf.ln(2)
            pdf.ln(6)

            # --- Section: Critical Incidents ---
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(122, 39, 39) 
            pdf.cell(0, 8, " 3. Critical Malware Incidents ", ln=True, fill=True)
            
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            if not self.critical_incidents:
                pdf.set_font("Arial", 'I', 10)
                pdf.set_text_color(33, 95, 61) 
                pdf.cell(0, 6, "Clear: No critical malware patterns were detected during this session.", ln=True)
            else:
                pdf.set_text_color(220, 0, 0) 
                for incident in self.critical_incidents:
                    pdf.multi_cell(0, 6, incident)
                    pdf.ln(1)
            pdf.ln(8)

            # --- Section: Full Session Log ---
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(255, 255, 255)
            pdf.set_fill_color(80, 80, 80) 
            pdf.cell(0, 8, " 4. Detailed Session Log ", ln=True, fill=True)
            
            pdf.set_font("Courier", '', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            for log in self.session_logs:
                pdf.multi_cell(0, 4, log)
                pdf.ln(0.5)

            # Save the PDF
            pdf.output(REPORT_PDF_FILE)
            self.log_message(f"SUCCESS: Professional PDF Report saved to '{REPORT_PDF_FILE}'.", success=True)
            messagebox.showinfo("Report Generated", f"Enterprise-grade PDF report has been saved as:\n{REPORT_PDF_FILE}")
            
        except Exception as e:
            self.log_message(f"ERROR: Failed to write PDF report. ({str(e)})", alert=True)

if __name__ == "__main__":
    app = RegistryMonitorApp()
    app.mainloop()