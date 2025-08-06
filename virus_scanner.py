#!/usr/bin/env python3
"""
Advanced Virus Scanner and Cleaner
A comprehensive security tool with GUI for detecting and removing malware
while protecting system-critical files.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import hashlib
import json
import re
import time
from pathlib import Path
import subprocess
import tempfile
from system_protection import SystemProtection
from scan_logger import ScanLogger

class VirusScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_gui()
        self.scan_running = False
        self.scan_results = []
        self.total_files = 0
        self.scanned_files = 0
        self.current_session_id = None
        
        # Initialize system protection and logging
        self.system_protection = SystemProtection()
        self.logger = ScanLogger()
        
        # Load virus signatures and system-critical files
        self.load_virus_signatures()
        self.load_critical_files()
        
    def setup_gui(self):
        """Setup the main GUI interface"""
        self.root.title("Advanced Virus Scanner & Cleaner")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Virus Scanner & Cleaner", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Scan options frame
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Scan type
        self.scan_type = tk.StringVar(value="quick")
        ttk.Radiobutton(options_frame, text="Quick Scan", variable=self.scan_type, 
                       value="quick").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(options_frame, text="Full System Scan", variable=self.scan_type, 
                       value="full").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(options_frame, text="Custom Folder", variable=self.scan_type, 
                       value="custom").grid(row=0, column=2, sticky=tk.W)
        
        # Custom folder selection
        self.custom_folder = tk.StringVar()
        ttk.Label(options_frame, text="Custom Folder:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        ttk.Entry(options_frame, textvariable=self.custom_folder, width=40).grid(row=1, column=1, padx=5, pady=(10, 0))
        ttk.Button(options_frame, text="Browse", command=self.browse_folder).grid(row=1, column=2, pady=(10, 0))
        
        # Control buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        self.start_button = ttk.Button(buttons_frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        self.clean_button = ttk.Button(buttons_frame, text="Clean Selected", command=self.clean_threats, state=tk.DISABLED)
        self.clean_button.grid(row=0, column=2, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Scan Progress", padding="10")
        progress_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(progress_frame, textvariable=self.progress_var).grid(row=0, column=0, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Results treeview
        columns = ("File", "Threat", "Risk Level", "Status")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Scrollbars for results
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Stats frame
        stats_frame = ttk.Frame(main_frame)
        stats_frame.grid(row=5, column=0, columnspan=3, pady=5)
        
        self.stats_var = tk.StringVar(value="Files Scanned: 0 | Threats Found: 0 | System Safe")
        ttk.Label(stats_frame, textvariable=self.stats_var).grid(row=0, column=0)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        options_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(0, weight=1)
        
    def load_virus_signatures(self):
        """Load virus signatures for detection"""
        try:
            # Try to load from external signature file
            if os.path.exists('signatures.json'):
                with open('signatures.json', 'r') as f:
                    signature_data = json.load(f)
                    self.virus_signatures = signature_data.get('virus_signatures', {})
            else:
                # Fallback to built-in signatures
                self.virus_signatures = {
                    'hashes': {
                        'd41d8cd98f00b204e9800998ecf8427e': 'Generic.Trojan.Empty',
                        '5d41402abc4b2a76b9719d911017c592': 'Adware.Generic.Hello',
                        '098f6bcd4621d373cade4e832627b4f6': 'Malware.Test.Sample',
                    },
                    'patterns': [
                        r'.*\.exe\.exe$',  # Double extensions
                        r'.*\.scr$',       # Screen savers (often malware)
                        r'.*\.pif$',       # Program information files
                        r'.*\.bat\.exe$',  # Suspicious batch-exe combinations
                        r'.*\.pdf\.exe$',  # Fake PDF files
                        r'.*\.doc\.exe$',  # Fake document files
                    ],
                    'strings': [
                        'eval(base64_decode',
                        'CreateObject("WScript.Shell")',
                        'powershell -enc',
                        'cmd.exe /c',
                        'regsvr32 /s',
                        'rundll32.exe',
                        'net user administrator',
                        'schtasks /create',
                    ]
                }
        except Exception as e:
            print(f"Error loading virus signatures: {e}")
            # Use minimal fallback signatures
            self.virus_signatures = {
                'hashes': {},
                'patterns': [r'.*\.exe\.exe$'],
                'strings': ['eval(base64_decode']
            }
        
    def load_critical_files(self):
        """Load list of system-critical files that should never be deleted"""
        self.critical_files = {
            # Windows system files
            'ntoskrnl.exe', 'ntdll.dll', 'kernel32.dll', 'user32.dll',
            'gdi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
            'advapi32.dll', 'rpcrt4.dll', 'comctl32.dll', 'comdlg32.dll',
            'wininet.dll', 'urlmon.dll', 'shlwapi.dll', 'version.dll',
            
            # Windows system executables
            'explorer.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'taskeng.exe',
            
            # Boot files
            'bootmgr', 'bootmgfw.efi', 'winload.exe', 'winresume.exe',
        }
        
        # Critical system directories
        self.critical_dirs = {
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Windows\\Boot',
            'C:\\Program Files\\Windows Defender',
            'C:\\Program Files\\Common Files\\Microsoft Shared',
        }
        
    def browse_folder(self):
        """Open folder selection dialog"""
        folder = filedialog.askdirectory()
        if folder:
            self.custom_folder.set(folder)
            
    def is_critical_file(self, filepath):
        """Check if file is system-critical and should not be deleted"""
        # Use the enhanced system protection module
        is_critical, reason = self.system_protection.is_critical_file(filepath)
        return is_critical
        
    def calculate_file_hash(self, filepath):
        """Calculate MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None
            
    def scan_file(self, filepath):
        """Scan a single file for threats"""
        try:
            if not os.path.isfile(filepath):
                return None
                
            threats = []
            
            # Check file hash against known malware
            file_hash = self.calculate_file_hash(filepath)
            if file_hash and file_hash in self.virus_signatures['hashes']:
                threats.append({
                    'type': 'hash_match',
                    'threat': self.virus_signatures['hashes'][file_hash],
                    'risk': 'High'
                })
                
            # Check filename patterns
            filename = os.path.basename(filepath)
            patterns = self.virus_signatures.get('patterns', [])
            for pattern in patterns:
                if re.match(pattern, filename, re.IGNORECASE):
                    threats.append({
                        'type': 'filename_pattern',
                        'threat': 'Suspicious filename pattern',
                        'risk': 'Medium'
                    })
                    
            # Check file content for suspicious strings (for text files)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10000)  # Read first 10KB
                    strings = self.virus_signatures.get('strings', [])
                    for suspicious_string in strings:
                        if suspicious_string in content:
                            threats.append({
                                'type': 'content_match',
                                'threat': f'Suspicious code: {suspicious_string[:30]}...',
                                'risk': 'High'
                            })
            except Exception:
                pass  # Binary file or read error, skip content scan
                
            return threats if threats else None
            
        except Exception as e:
            print(f"Error scanning file {filepath}: {e}")
            return None
            
    def get_scan_paths(self):
        """Get list of paths to scan based on selected scan type"""
        if self.scan_type.get() == "quick":
            # Quick scan: common malware locations
            paths = [
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\Documents"),
                "C:\\Users\\Public",
                tempfile.gettempdir(),
            ]
        elif self.scan_type.get() == "custom":
            custom_path = self.custom_folder.get()
            if not custom_path or not os.path.exists(custom_path):
                messagebox.showerror("Error", "Please select a valid folder for custom scan")
                return []
            paths = [custom_path]
        else:  # full scan
            paths = ["C:\\"]
            
        return paths
        
    def count_files(self, paths):
        """Count total files to scan"""
        total = 0
        for path in paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    total += len(files)
        return total
        
    def scan_thread(self):
        """Main scanning thread"""
        try:
            self.scan_results = []
            paths = self.get_scan_paths()
            
            if not paths:
                return
                
            # Count total files
            self.progress_var.set("Counting files...")
            self.root.update()
            self.total_files = self.count_files(paths)
            self.scanned_files = 0
            
            if self.total_files == 0:
                self.progress_var.set("No files found to scan")
                return
                
            self.progress_bar['maximum'] = self.total_files
            
            # Scan files
            for path in paths:
                if not self.scan_running:
                    break
                    
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        if not self.scan_running:
                            break
                            
                        for file in files:
                            if not self.scan_running:
                                break
                                
                            filepath = os.path.join(root, file)
                            self.scanned_files += 1
                            
                            # Update progress
                            self.progress_var.set(f"Scanning: {file}")
                            self.progress_bar['value'] = self.scanned_files
                            self.root.update()
                            
                            # Scan file
                            threats = self.scan_file(filepath)
                            if threats:
                                for threat in threats:
                                    self.scan_results.append({
                                        'filepath': filepath,
                                        'filename': file,
                                        'threat': threat['threat'],
                                        'risk': threat['risk'],
                                        'critical': self.is_critical_file(filepath)
                                    })
                                    
            # Update results display
            self.update_results_display()
            
            if self.scan_running:
                self.progress_var.set("Scan completed")
                threats_found = len(self.scan_results)
                if threats_found > 0:
                    messagebox.showwarning("Scan Complete", 
                                         f"Scan completed! Found {threats_found} potential threats.")
                else:
                    messagebox.showinfo("Scan Complete", "Scan completed! No threats detected.")
            
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
        finally:
            self.scan_finished()
            
    def update_results_display(self):
        """Update the results tree view"""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Add new results
        for result in self.scan_results:
            status = "CRITICAL SYSTEM FILE" if result['critical'] else "Safe to remove"
            self.results_tree.insert('', 'end', values=(
                result['filename'],
                result['threat'],
                result['risk'],
                status
            ))
            
        # Update stats
        threats_count = len(self.scan_results)
        status = "THREATS DETECTED" if threats_count > 0 else "System Safe"
        self.stats_var.set(f"Files Scanned: {self.scanned_files} | Threats Found: {threats_count} | {status}")
        
        # Enable clean button if threats found
        if threats_count > 0:
            self.clean_button.config(state=tk.NORMAL)
            
    def start_scan(self):
        """Start the scanning process"""
        if not self.scan_running:
            self.scan_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.clean_button.config(state=tk.DISABLED)
            
            # Start scanning in a separate thread
            scan_thread = threading.Thread(target=self.scan_thread)
            scan_thread.daemon = True
            scan_thread.start()
            
    def stop_scan(self):
        """Stop the scanning process"""
        self.scan_running = False
        self.progress_var.set("Stopping scan...")
        
    def scan_finished(self):
        """Called when scan is finished"""
        self.scan_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
    def clean_threats(self):
        """Clean selected threats"""
        selected_items = self.results_tree.selection()
        if not selected_items:
            # If nothing selected, ask if user wants to clean all
            result = messagebox.askyesno("Clean All", 
                                       "No items selected. Do you want to clean all detected threats?")
            if result:
                selected_items = self.results_tree.get_children()
            else:
                return
                
        # Get files to clean
        files_to_clean = []
        critical_files = []
        
        for item in selected_items:
            values = self.results_tree.item(item)['values']
            filename = values[0]
            status = values[3]
            
            # Find the full path
            for result in self.scan_results:
                if result['filename'] == filename:
                    if result['critical']:
                        critical_files.append(result['filepath'])
                    else:
                        files_to_clean.append(result['filepath'])
                    break
                    
        # Warn about critical files
        if critical_files:
            critical_list = '\n'.join([os.path.basename(f) for f in critical_files[:5]])
            if len(critical_files) > 5:
                critical_list += f'\n... and {len(critical_files) - 5} more'
                
            messagebox.showwarning("Critical Files Detected", 
                                 f"The following system-critical files will NOT be deleted:\n\n{critical_list}\n\n" +
                                 "These files are essential for system operation.")
        
        if not files_to_clean:
            messagebox.showinfo("Nothing to Clean", "No files can be safely cleaned.")
            return
            
        # Confirm cleaning
        file_list = '\n'.join([os.path.basename(f) for f in files_to_clean[:10]])
        if len(files_to_clean) > 10:
            file_list += f'\n... and {len(files_to_clean) - 10} more'
            
        result = messagebox.askyesno("Confirm Cleaning", 
                                   f"Are you sure you want to delete the following {len(files_to_clean)} files?\n\n{file_list}")
        
        if result:
            cleaned_count = 0
            failed_count = 0
            
            for filepath in files_to_clean:
                try:
                    os.remove(filepath)
                    cleaned_count += 1
                except Exception as e:
                    failed_count += 1
                    print(f"Failed to delete {filepath}: {e}")
                    
            # Show results
            if failed_count > 0:
                messagebox.showwarning("Cleaning Complete", 
                                     f"Cleaning completed!\n\nSuccessfully removed: {cleaned_count} files\nFailed to remove: {failed_count} files")
            else:
                messagebox.showinfo("Cleaning Complete", 
                                  f"Successfully removed {cleaned_count} threat files!")
                                  
            # Refresh results
            self.start_scan()
            
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = VirusScanner()
    app.run()
