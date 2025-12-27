#!/usr/bin/env python3
"""
Main Application Entry Point for AI Cybersecurity Platform
A Unified Platform for Automated Cybersecurity Vulnerability Assessment
in Machine Learning Models and AI Agents

Author: Mohamed Massaoudi, PhD
Resilient Energy Systems Lab, Texas A&M University
Email: mohamed.massaoudi@tamu.edu
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
import json
from datetime import datetime
import webbrowser
import tempfile

# Handle PIL/Pillow import with fallback
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: PIL/Pillow not available. Logo will not be displayed.")

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    return os.path.join(base_path, relative_path)

# Add the ai_cybersecurity package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.path.insert(0, get_resource_path(''))
except:
    pass

from ai_cybersecurity import MLScanner, AgentScanner, VulnerabilityLevel
from ai_cybersecurity.utils import create_vulnerability_summary, format_file_size, format_timestamp
from ai_cybersecurity.immunization import ModelImmunizer

class AISecurityGUI:
    """Main GUI application for AI Cybersecurity Platform."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("AI Cybersecurity Platform v2.0 - Enhanced Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize scanners
        self.ml_scanner = MLScanner()
        self.agent_scanner = AgentScanner()
        self.immunizer = ModelImmunizer()
        
        # Current scan results
        self.current_results = []
        self.current_file_path = None
        self.scan_in_progress = False
        
        # Load logo
        self.logo_image = self.load_logo()
        
        self.setup_menu()
        self.setup_ui()
    
    def load_logo(self):
        """Load the application logo."""
        if not PIL_AVAILABLE:
            print("PIL not available, cannot load logo")
            return None
        
        try:
            # Try multiple paths to find the logo
            possible_paths = [
                get_resource_path("logo.png"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png"),
                os.path.join(os.getcwd(), "logo.png"),
                os.path.join(os.path.dirname(sys.executable), "logo.png"),
                "logo.png",
                # Also try in parent directories
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logo.png"),
            ]
            
            # Add _MEIPASS paths explicitly
            if hasattr(sys, '_MEIPASS'):
                possible_paths.insert(0, os.path.join(sys._MEIPASS, "logo.png"))
            
            print(f"Searching for logo in: {possible_paths}")
            
            for logo_path in possible_paths:
                print(f"Checking: {logo_path} - Exists: {os.path.exists(logo_path)}")
                if os.path.exists(logo_path):
                    try:
                        img = Image.open(logo_path)
                        print(f"Logo loaded successfully from: {logo_path}")
                        # Resize logo to fit in the interface
                        img = img.resize((64, 64), Image.Resampling.LANCZOS)
                        photo = ImageTk.PhotoImage(img)
                        
                        # Also set as window icon
                        try:
                            icon_img = Image.open(logo_path)
                            icon_img = icon_img.resize((32, 32), Image.Resampling.LANCZOS)
                            self.icon_image = ImageTk.PhotoImage(icon_img)
                            self.root.iconphoto(True, self.icon_image)
                        except Exception as icon_e:
                            print(f"Could not set window icon: {icon_e}")
                        
                        return photo
                    except Exception as inner_e:
                        print(f"Could not load logo from {logo_path}: {inner_e}")
                        continue
            
            print(f"Logo not found in any of the searched paths")
            
        except Exception as e:
            print(f"Could not load logo: {e}")
        
        return None
    
    def setup_menu(self):
        """Setup the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Model/Agent...", command=self.browse_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Start Scan", command=self.start_scan, accelerator="F5")
        tools_menu.add_command(label="Immunize Model", command=self.immunize_model, accelerator="Ctrl+I")
        tools_menu.add_separator()
        tools_menu.add_command(label="Generate Report", command=self.generate_report, accelerator="Ctrl+R")
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_help)
        help_menu.add_command(label="Contact", command=self.show_contact)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-o>', lambda e: self.browse_file())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F5>', lambda e: self.start_scan())
        self.root.bind('<Control-i>', lambda e: self.immunize_model())
        self.root.bind('<Control-r>', lambda e: self.generate_report())
    
    def setup_ui(self):
        """Setup the user interface."""
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Header frame with logo and title
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Logo
        if self.logo_image:
            logo_label = ttk.Label(header_frame, image=self.logo_image)
            logo_label.pack(side=tk.LEFT, padx=(0, 20))
        
        # Title and subtitle
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)
        
        title_label = ttk.Label(title_frame, text="🛡️ AI Cybersecurity Platform", 
                               font=('Arial', 18, 'bold'))
        title_label.pack(anchor=tk.W)
        
        subtitle_label = ttk.Label(title_frame, text="Enhanced Edition v2.0 - Advanced Threat Detection & Model Immunization", 
                                  font=('Arial', 10, 'italic'), foreground='#666')
        subtitle_label.pack(anchor=tk.W)
        
        author_label = ttk.Label(title_frame, text="By Mohamed Massaoudi, PhD - Texas A&M University", 
                                font=('Arial', 9), foreground='#888')
        author_label.pack(anchor=tk.W)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="Target File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=60)
        self.file_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2)
        
        # Scan type selection
        scan_frame = ttk.LabelFrame(main_frame, text="Scan Type", padding="10")
        scan_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.scan_type = tk.StringVar(value="auto")
        ttk.Radiobutton(scan_frame, text="Auto-detect", variable=self.scan_type, 
                       value="auto").grid(row=0, column=0, padx=(0, 20))
        ttk.Radiobutton(scan_frame, text="ML Model", variable=self.scan_type, 
                       value="ml").grid(row=0, column=1, padx=(0, 20))
        ttk.Radiobutton(scan_frame, text="AI Agent", variable=self.scan_type, 
                       value="agent").grid(row=0, column=2, padx=(0, 20))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="🔍 Start Scan", 
                                     command=self.start_scan, style="Accent.TButton")
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.immunize_button = ttk.Button(button_frame, text="🛡️ Immunize Model", 
                                         command=self.immunize_model, state='disabled')
        self.immunize_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="📄 Generate Report", 
                  command=self.generate_report).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="🗑️ Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="❓ Help", 
                  command=self.show_help).pack(side=tk.RIGHT, padx=(10, 0))
        
        ttk.Button(button_frame, text="📧 Contact", 
                  command=self.show_contact).pack(side=tk.RIGHT)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                       mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Summary frame
        summary_frame = ttk.Frame(results_frame)
        summary_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        summary_frame.columnconfigure(4, weight=1)
        
        self.summary_labels = {}
        labels = [
            ("Total:", "total", "blue"),
            ("Critical:", "critical", "red"),
            ("High:", "high", "orange"),
            ("Medium:", "medium", "gold"),
            ("Low:", "low", "green")
        ]
        
        for i, (text, key, color) in enumerate(labels):
            ttk.Label(summary_frame, text=text).grid(row=0, column=i*2, padx=(0, 5))
            label = ttk.Label(summary_frame, text="0", foreground=color, font=('Arial', 10, 'bold'))
            label.grid(row=0, column=i*2+1, padx=(0, 20))
            self.summary_labels[key] = label
        
        # Results treeview
        columns = ("Severity", "Title", "Description", "Remediation")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.results_tree.heading("Severity", text="Severity")
        self.results_tree.heading("Title", text="Title")
        self.results_tree.heading("Description", text="Description")
        self.results_tree.heading("Remediation", text="Remediation")
        
        self.results_tree.column("Severity", width=100, minwidth=80)
        self.results_tree.column("Title", width=200, minwidth=150)
        self.results_tree.column("Description", width=300, minwidth=200)
        self.results_tree.column("Remediation", width=300, minwidth=200)
        
        # Scrollbars for treeview
        tree_scroll_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        tree_scroll_x = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        self.results_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll_y.grid(row=1, column=1, sticky=(tk.N, tk.S))
        tree_scroll_x.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - AI Cybersecurity Platform v2.0")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure severity colors
        self.results_tree.tag_configure("CRITICAL", background="#ffebee")
        self.results_tree.tag_configure("HIGH", background="#fff3e0")
        self.results_tree.tag_configure("MEDIUM", background="#f3e5f5")
        self.results_tree.tag_configure("LOW", background="#e8f5e8")
    
    def browse_file(self):
        """Open file browser to select target file."""
        file_types = [
            ("All Supported", "*.pkl;*.joblib;*.h5;*.hdf5;*.onnx;*.pth;*.pt;*.py"),
            ("Python Files", "*.py"),
            ("Pickle Files", "*.pkl"),
            ("Joblib Files", "*.joblib"),
            ("TensorFlow Models", "*.h5;*.hdf5"),
            ("ONNX Models", "*.onnx"),
            ("PyTorch Models", "*.pth;*.pt"),
            ("All Files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select ML Model or AI Agent File",
            filetypes=file_types
        )
        
        if filename:
            self.file_path_var.set(filename)
            self.current_file_path = filename
            
            # Enable immunize button for ML model files (pkl, joblib)
            file_ext = Path(filename).suffix.lower()
            if file_ext in ['.pkl', '.pickle', '.joblib']:
                self.immunize_button.config(state='normal')
                self.status_var.set(f"ML Model selected: {Path(filename).name} - Ready to scan or immunize")
            else:
                self.immunize_button.config(state='disabled')
                self.status_var.set(f"File selected: {Path(filename).name} - Click Start Scan")
    
    def start_scan(self):
        """Start vulnerability scan in separate thread."""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
        
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showerror("No File Selected", "Please select a file to scan.")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"The selected file does not exist:\n{file_path}")
            return
        
        # Start scan in separate thread
        self.scan_in_progress = True
        self.scan_button.config(state='disabled')
        self.progress.start()
        self.status_var.set("Scanning...")
        
        thread = threading.Thread(target=self.run_scan, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def run_scan(self, file_path):
        """Run the actual scan (called in separate thread)."""
        try:
            path_obj = Path(file_path)
            scan_type = self.scan_type.get()
            
            # Auto-detect scan type if needed
            if scan_type == "auto":
                if path_obj.suffix.lower() == ".py":
                    scan_type = "agent"
                else:
                    scan_type = "ml"
            
            # Run appropriate scanner
            if scan_type == "ml":
                self.status_var.set("Scanning ML model...")
                vulnerabilities = self.ml_scanner.scan_model(path_obj)
            else:
                self.status_var.set("Scanning AI agent...")
                vulnerabilities = self.agent_scanner.scan_agent(path_obj)
            
            # Update UI in main thread
            self.root.after(0, self.scan_complete, vulnerabilities, file_path)
            
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_complete(self, vulnerabilities, file_path):
        """Handle scan completion (called in main thread)."""
        self.scan_in_progress = False
        self.scan_button.config(state='normal')
        self.progress.stop()
        
        self.current_results = vulnerabilities
        self.current_file_path = file_path
        self.display_results(vulnerabilities)
        
        # Enable immunize button for ML models with vulnerabilities
        scan_type = self.scan_type.get()
        if scan_type in ["auto", "ml"] and vulnerabilities and Path(file_path).suffix.lower() in ['.pkl', '.pickle', '.joblib']:
            self.immunize_button.config(state='normal')
        else:
            self.immunize_button.config(state='disabled')
        
        scan_summary = create_vulnerability_summary(vulnerabilities)
        self.status_var.set(f"Scan complete: {scan_summary['total']} vulnerabilities found")
        
        if scan_summary['total'] == 0:
            messagebox.showinfo("Scan Complete", "✅ No vulnerabilities found! The file appears to be secure.")
        else:
            messagebox.showwarning("Scan Complete", 
                                 f"⚠️ Found {scan_summary['total']} vulnerabilities.\n"
                                 f"Risk Score: {scan_summary['risk_score']:.2f}/4.0")
    
    def scan_error(self, error_message):
        """Handle scan error (called in main thread)."""
        self.scan_in_progress = False
        self.scan_button.config(state='normal')
        self.progress.stop()
        self.status_var.set("Scan failed")
        
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n\n{error_message}")
    
    def display_results(self, vulnerabilities):
        """Display scan results in the treeview."""
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Update summary
        summary = create_vulnerability_summary(vulnerabilities)
        self.summary_labels["total"].config(text=str(summary["total"]))
        
        for level in VulnerabilityLevel:
            count = summary["by_severity"].get(level.value, 0)
            self.summary_labels[level.value].config(text=str(count))
        
        # Add vulnerabilities to tree
        for vuln in vulnerabilities:
            # Truncate long descriptions for display
            description = vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description
            remediation = vuln.remediation[:100] + "..." if len(vuln.remediation) > 100 else vuln.remediation
            
            item = self.results_tree.insert("", tk.END, values=(
                vuln.level.value.upper(),
                vuln.title,
                description,
                remediation
            ), tags=(vuln.level.value.upper(),))
    
    def generate_report(self):
        """Generate and save detailed report."""
        if not self.current_results:
            messagebox.showwarning("No Results", "No scan results available. Please run a scan first.")
            return
        
        # Ask user for save location
        filename = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".html",
            filetypes=[
                ("HTML Report", "*.html"),
                ("JSON Report", "*.json"),
                ("Text Report", "*.txt")
            ]
        )
        
        if not filename:
            return
        
        try:
            file_ext = Path(filename).suffix.lower()
            
            if file_ext == ".html":
                self.generate_html_report(filename)
            elif file_ext == ".json":
                self.generate_json_report(filename)
            else:
                self.generate_text_report(filename)
            
            messagebox.showinfo("Report Generated", f"Report saved successfully:\n{filename}")
            
            # Ask if user wants to open the report
            if file_ext == ".html" and messagebox.askyesno("Open Report", "Would you like to open the report in your browser?"):
                webbrowser.open(f"file://{os.path.abspath(filename)}")
                
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report:\n\n{str(e)}")
    
    def generate_html_report(self, filename):
        """Generate HTML report."""
        summary = create_vulnerability_summary(self.current_results)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Cybersecurity Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .vulnerability {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
        .critical {{ background: #ffebee; border-left: 5px solid #f44336; }}
        .high {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
        .medium {{ background: #f3e5f5; border-left: 5px solid #9c27b0; }}
        .low {{ background: #e8f5e8; border-left: 5px solid #4caf50; }}
        .title {{ font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }}
        .description {{ margin-bottom: 10px; }}
        .remediation {{ font-style: italic; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Cybersecurity Scan Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {summary['total']}</p>
        <p><strong>Risk Score:</strong> {summary['risk_score']:.2f}/4.0</p>
        <p><strong>By Severity:</strong></p>
        <ul>
            <li>Critical: {summary['by_severity'].get('critical', 0)}</li>
            <li>High: {summary['by_severity'].get('high', 0)}</li>
            <li>Medium: {summary['by_severity'].get('medium', 0)}</li>
            <li>Low: {summary['by_severity'].get('low', 0)}</li>
        </ul>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        for vuln in self.current_results:
            html_content += f"""
    <div class="vulnerability {vuln.level.value}">
        <div class="title">{vuln.level.value.upper()}: {vuln.title}</div>
        <div class="description">{vuln.description}</div>
        <div class="remediation"><strong>Remediation:</strong> {vuln.remediation}</div>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_json_report(self, filename):
        """Generate JSON report."""
        report_data = {
            "scan_timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(self.current_results),
            "summary": create_vulnerability_summary(self.current_results),
            "vulnerabilities": [vuln.to_dict() for vuln in self.current_results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def generate_text_report(self, filename):
        """Generate text report."""
        summary = create_vulnerability_summary(self.current_results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("AI CYBERSECURITY SCAN REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Vulnerabilities: {summary['total']}\n")
            f.write(f"Risk Score: {summary['risk_score']:.2f}/4.0\n\n")
            
            f.write("SUMMARY BY SEVERITY:\n")
            f.write("-" * 20 + "\n")
            for level in ['critical', 'high', 'medium', 'low']:
                count = summary['by_severity'].get(level, 0)
                f.write(f"{level.capitalize()}: {count}\n")
            
            f.write("\n\nDETAILED FINDINGS:\n")
            f.write("-" * 20 + "\n\n")
            
            for i, vuln in enumerate(self.current_results, 1):
                f.write(f"{i}. {vuln.level.value.upper()}: {vuln.title}\n")
                f.write(f"   Description: {vuln.description}\n")
                f.write(f"   Remediation: {vuln.remediation}\n\n")
    
    def clear_results(self):
        """Clear all scan results."""
        if messagebox.askyesno("Clear Results", "Are you sure you want to clear all results?"):
            self.current_results = []
            self.current_file_path = None
            self.immunize_button.config(state='disabled')
            self.display_results([])
            self.status_var.set("Ready")
    
    def immunize_model(self):
        """Immunize the model against vulnerabilities with protective wrappers."""
        # Get file path from entry if not set
        if not self.current_file_path:
            self.current_file_path = self.file_path_var.get().strip()
        
        if not self.current_file_path:
            messagebox.showwarning("No File Selected", "Please select an ML model file first.")
            return
        
        if not os.path.exists(self.current_file_path):
            messagebox.showerror("File Not Found", f"The selected file does not exist:\n{self.current_file_path}")
            return
        
        # Check if it's an ML model
        if Path(self.current_file_path).suffix.lower() not in ['.pkl', '.pickle', '.joblib']:
            messagebox.showerror("Unsupported Format", "Model immunization is currently only supported for .pkl, .pickle, and .joblib files.")
            return
        
        # If no scan results, create default protective vulnerabilities
        vulnerabilities_to_address = self.current_results if self.current_results else []
        
        # If no vulnerabilities found, add default protection types
        if not vulnerabilities_to_address:
            from ai_cybersecurity.utils import VulnerabilityReport
            # Create default protection recommendations
            default_protections = [
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Insecure Serialization (Preventive)",
                    description="Applying secure serialization wrapper to protect against potential deserialization attacks.",
                    remediation="Secure serialization protection will be applied."
                ),
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Input Validation (Preventive)",
                    description="Adding input validation layer to protect against malformed inputs.",
                    remediation="Input validation protection will be applied."
                ),
                VulnerabilityReport(
                    level=VulnerabilityLevel.LOW,
                    title="Metadata Protection (Preventive)",
                    description="Adding metadata protection to ensure model integrity.",
                    remediation="Metadata protection will be applied."
                ),
            ]
            vulnerabilities_to_address = default_protections
        
        # Show protection options dialog
        protection_dialog = tk.Toplevel(self.root)
        protection_dialog.title("Model Immunization Options")
        protection_dialog.geometry("500x450")
        protection_dialog.transient(self.root)
        protection_dialog.grab_set()
        
        # Center the dialog
        protection_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(protection_dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="🛡️ Model Immunization", font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Info label
        if not self.current_results:
            ttk.Label(main_frame, text="No scan performed - applying preventive protection", 
                     font=('Arial', 9, 'italic'), foreground='#666').pack(pady=(0, 10))
        
        # Protection level selection
        ttk.Label(main_frame, text="Protection Level:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        protection_level = tk.StringVar(value="standard")
        ttk.Radiobutton(main_frame, text="Basic - Fast protection with minimal performance impact", 
                       variable=protection_level, value="basic").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(main_frame, text="Standard - Balanced protection and performance", 
                       variable=protection_level, value="standard").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(main_frame, text="Maximum - Comprehensive protection (may impact performance)", 
                       variable=protection_level, value="maximum").pack(anchor=tk.W, pady=2)
        
        # Protections to apply
        ttk.Label(main_frame, text=f"\nProtections to Apply ({len(vulnerabilities_to_address)}):", 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(20, 5))
        
        # Store for use in nested function
        self._temp_vulnerabilities = vulnerabilities_to_address
        
        # Scrollable list of vulnerabilities/protections
        vuln_frame = ttk.Frame(main_frame)
        vuln_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        vuln_listbox = tk.Listbox(vuln_frame, height=6)
        vuln_scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=vuln_listbox.yview)
        vuln_listbox.configure(yscrollcommand=vuln_scrollbar.set)
        
        vuln_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vuln_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        for vuln in vulnerabilities_to_address:
            vuln_listbox.insert(tk.END, f"[{vuln.level.value.upper()}] {vuln.title}")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def start_immunization():
            protection_dialog.destroy()
            self.run_immunization(protection_level.get())
        
        ttk.Button(button_frame, text="🛡️ Start Immunization", 
                  command=start_immunization, style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", 
                  command=protection_dialog.destroy).pack(side=tk.LEFT)
        
        # Info label
        info_label = ttk.Label(main_frame, text="⚠️ The original model will be preserved. A new immunized version will be created.", 
                              font=('Arial', 9), foreground='#666')
        info_label.pack(pady=(20, 0))
    
    def run_immunization(self, protection_level):
        """Run the immunization process."""
        if not self.current_file_path:
            messagebox.showerror("Error", "No file path specified.")
            return
        
        # Use temp vulnerabilities if current_results is empty
        vulnerabilities = self._temp_vulnerabilities if hasattr(self, '_temp_vulnerabilities') and self._temp_vulnerabilities else self.current_results
        
        if not vulnerabilities:
            messagebox.showerror("Error", "No vulnerabilities or protections to apply.")
            return
        
        # Store for worker thread
        self._immunize_vulnerabilities = vulnerabilities
        
        # Disable buttons during immunization
        self.immunize_button.config(state='disabled')
        self.scan_button.config(state='disabled')
        
        # Show progress
        self.progress.start()
        self.status_var.set("Immunizing model...")
        
        # Run immunization in separate thread
        thread = threading.Thread(target=self.immunize_worker, args=(protection_level,))
        thread.daemon = True
        thread.start()
    
    def immunize_worker(self, protection_level):
        """Worker thread for immunization."""
        try:
            # Get vulnerabilities to address
            vulnerabilities = self._immunize_vulnerabilities if hasattr(self, '_immunize_vulnerabilities') else self.current_results
            
            # Run immunization
            result = self.immunizer.immunize_model(
                self.current_file_path, 
                vulnerabilities, 
                protection_level
            )
            
            # Update UI in main thread
            self.root.after(0, self.immunization_complete, result)
            
        except Exception as e:
            self.root.after(0, self.immunization_error, str(e))
    
    def immunization_complete(self, result):
        """Handle immunization completion."""
        self.immunize_button.config(state='normal')
        self.scan_button.config(state='normal')
        self.progress.stop()
        
        if result['status'] == 'success':
            self.status_var.set("Model immunization complete")
            
            # Show success dialog with details
            success_dialog = tk.Toplevel(self.root)
            success_dialog.title("Immunization Complete")
            success_dialog.geometry("600x500")
            success_dialog.transient(self.root)
            success_dialog.grab_set()
            
            # Center the dialog
            success_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
            
            main_frame = ttk.Frame(success_dialog, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Title
            ttk.Label(main_frame, text="✅ Model Immunization Successful!", 
                     font=('Arial', 14, 'bold'), foreground='green').pack(pady=(0, 20))
            
            # Results
            ttk.Label(main_frame, text="Immunization Results:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
            
            results_text = scrolledtext.ScrolledText(main_frame, height=15, width=70)
            results_text.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
            
            # Format results
            report = result['report']
            results_content = f"""Original Model: {report['original_model']}
Immunized Model: {report['immunized_model']}

Protection Summary:
• Total Vulnerabilities: {report['total_vulnerabilities']}
• Successfully Protected: {report['successful_protections']}
• Protection Rate: {report['protection_rate']:.1%}

Vulnerabilities Addressed:
"""
            for vuln in report['vulnerabilities_addressed']:
                results_content += f"• {vuln}\n"
            
            results_content += f"\nProtection Methods Applied:\n"
            for method in report['protection_methods_applied']:
                results_content += f"• {method.replace('_', ' ').title()}\n"
            
            if report['failed_protections']:
                results_content += f"\nFailed Protections:\n"
                for failed in report['failed_protections']:
                    results_content += f"• {failed}\n"
            
            results_content += f"\nRecommendations:\n"
            for rec in report['recommendations']:
                results_content += f"• {rec}\n"
            
            results_text.insert(tk.END, results_content)
            results_text.config(state='disabled')
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)
            
            def open_immunized_model():
                immunized_path = result['immunized_path']
                if os.path.exists(immunized_path):
                    try:
                        # Windows
                        if sys.platform == 'win32':
                            os.startfile(os.path.dirname(immunized_path))
                        # macOS
                        elif sys.platform == 'darwin':
                            import subprocess
                            subprocess.run(['open', os.path.dirname(immunized_path)])
                        # Linux
                        else:
                            import subprocess
                            subprocess.run(['xdg-open', os.path.dirname(immunized_path)])
                    except Exception as e:
                        messagebox.showinfo("Immunized Model Location", 
                                          f"Immunized model saved at:\n{immunized_path}")
                else:
                    messagebox.showerror("File Not Found", f"Immunized model not found at: {immunized_path}")
            
            ttk.Button(button_frame, text="📁 Open Immunized Model Location", 
                      command=open_immunized_model).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Button(button_frame, text="Close", 
                      command=success_dialog.destroy).pack(side=tk.LEFT)
            
        else:
            self.status_var.set("Model immunization failed")
            messagebox.showerror("Immunization Failed", f"Failed to immunize model:\n\n{result.get('error', 'Unknown error')}")
    
    def immunization_error(self, error_message):
        """Handle immunization error."""
        self.immunize_button.config(state='normal')
        self.scan_button.config(state='normal')
        self.progress.stop()
        self.status_var.set("Immunization failed")
        
        messagebox.showerror("Immunization Error", f"An error occurred during immunization:\n\n{error_message}")
    
    def show_help(self):
        """Show help dialog."""
        help_text = """
AI CYBERSECURITY PLATFORM HELP

This tool helps you identify cybersecurity vulnerabilities in:
• Machine Learning models (.pkl, .joblib, .h5, .onnx, .pth, .pt)
• AI agents (Python .py files)

HOW TO USE:
1. Click "Browse" to select your ML model or AI agent file
2. Choose scan type (or leave on Auto-detect)
3. Click "Start Scan" to begin vulnerability assessment
4. Review results in the table below
5. For ML models with vulnerabilities, click "Immunize Model" to create a protected version
6. Generate detailed reports in HTML, JSON, or text format

MODEL IMMUNIZATION:
• Automatically applies protection against detected vulnerabilities
• Creates a new immunized model (original is preserved)
• Supports multiple protection levels: Basic, Standard, Maximum
• Protection methods include: adversarial training, secure serialization, 
  input validation, differential privacy, and explainability layers

VULNERABILITY LEVELS:
• CRITICAL: Immediate security threats requiring urgent action
• HIGH: Serious vulnerabilities that should be addressed soon
• MEDIUM: Moderate security issues worth investigating
• LOW: Minor issues or best practice recommendations

For technical support or questions, refer to the documentation.
"""
        
        help_window = tk.Toplevel(self.root)
        help_window.title("Help - AI Cybersecurity Platform")
        help_window.geometry("600x500")
        help_window.transient(self.root)
        help_window.grab_set()
        
        text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, padx=20, pady=20)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=10)

    def show_contact(self):
        """Show contact information dialog."""
        contact_window = tk.Toplevel(self.root)
        contact_window.title("Contact Information")
        contact_window.geometry("500x300")
        contact_window.transient(self.root)
        contact_window.grab_set()
        contact_window.configure(bg='#f0f0f0')
        
        # Main frame
        main_frame = ttk.Frame(contact_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Contact Information", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Contact details
        contact_frame = ttk.Frame(main_frame)
        contact_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Author info
        ttk.Label(contact_frame, text="Author:", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        ttk.Label(contact_frame, text="Mohamed Massaoudi, PhD", 
                 font=('Arial', 11)).pack(anchor=tk.W, padx=(20, 0))
        
        ttk.Label(contact_frame, text="", font=('Arial', 8)).pack()  # Spacer
        
        # Affiliation
        ttk.Label(contact_frame, text="Affiliation:", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        ttk.Label(contact_frame, text="Resilient Energy Systems Lab", 
                 font=('Arial', 11)).pack(anchor=tk.W, padx=(20, 0))
        ttk.Label(contact_frame, text="Texas A&M University", 
                 font=('Arial', 11)).pack(anchor=tk.W, padx=(20, 0))
        
        ttk.Label(contact_frame, text="", font=('Arial', 8)).pack()  # Spacer
        
        # Email
        ttk.Label(contact_frame, text="Email:", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        email_frame = ttk.Frame(contact_frame)
        email_frame.pack(anchor=tk.W, padx=(20, 0))
        
        email_label = ttk.Label(email_frame, text="mohamed.massaoudi@tamu.edu", 
                               font=('Arial', 11), foreground='blue', cursor='hand2')
        email_label.pack(side=tk.LEFT)
        
        def open_email():
            webbrowser.open("mailto:mohamed.massaoudi@tamu.edu")
        
        email_label.bind("<Button-1>", lambda e: open_email())
        
        # Research focus
        ttk.Label(contact_frame, text="", font=('Arial', 8)).pack()  # Spacer
        ttk.Label(contact_frame, text="Research Focus:", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        ttk.Label(contact_frame, text="• AI/ML Security and Cybersecurity", 
                 font=('Arial', 10)).pack(anchor=tk.W, padx=(20, 0))
        ttk.Label(contact_frame, text="• Resilient Energy Systems", 
                 font=('Arial', 10)).pack(anchor=tk.W, padx=(20, 0))
        ttk.Label(contact_frame, text="• Automated Vulnerability Assessment", 
                 font=('Arial', 10)).pack(anchor=tk.W, padx=(20, 0))
        
        # Close button
        ttk.Button(main_frame, text="Close", command=contact_window.destroy).pack(pady=(20, 0))
    
    def show_about(self):
        """Show about dialog."""
        about_window = tk.Toplevel(self.root)
        about_window.title("About AI Cybersecurity Platform")
        about_window.geometry("600x400")
        about_window.transient(self.root)
        about_window.grab_set()
        about_window.configure(bg='#f0f0f0')
        
        # Main frame
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo and title
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        if self.logo_image:
            logo_label = ttk.Label(header_frame, image=self.logo_image)
            logo_label.pack(side=tk.LEFT, padx=(0, 20))
        
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)
        
        ttk.Label(title_frame, text="AI Cybersecurity Platform", 
                 font=('Arial', 18, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Enhanced Edition v2.0", 
                 font=('Arial', 12, 'italic')).pack(anchor=tk.W)
        
        # Description
        desc_text = """
A Unified Platform for Automated Cybersecurity Vulnerability Assessment
in Machine Learning Models and AI Agents

This advanced platform provides comprehensive security analysis and 
protection for AI/ML systems, featuring:

• Automated vulnerability detection for ML models and AI agents
• Advanced model immunization with cutting-edge protection methods
• Adversarial training and defense mechanisms
• Secure model encryption and obfuscation
• Differential privacy implementation
• Comprehensive reporting and analysis tools

Developed at the Resilient Energy Systems Lab, Texas A&M University
"""
        
        desc_label = ttk.Label(main_frame, text=desc_text, font=('Arial', 10), 
                              justify=tk.LEFT, wraplength=550)
        desc_label.pack(fill=tk.X, pady=(0, 20))
        
        # Version info
        version_frame = ttk.Frame(main_frame)
        version_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(version_frame, text="Version: 2.0.0", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        ttk.Label(version_frame, text="Release Date: January 2025", font=('Arial', 10)).pack(anchor=tk.W)
        ttk.Label(version_frame, text="License: Academic Research Use", font=('Arial', 10)).pack(anchor=tk.W)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=about_window.destroy).pack(pady=(20, 0))

def main():
    """Main entry point."""
    root = tk.Tk()
    app = AISecurityGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main() 