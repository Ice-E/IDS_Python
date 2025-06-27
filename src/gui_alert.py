import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import queue

class IDS_GUI:
    def __init__(self, start_callback, attack_callback):
        self.root = tk.Tk()
        self.root.title("Intrusion Detection System")
        self.root.geometry("700x500")

        self.alert_queue = queue.Queue()
        self.ip_counts = {}

        # Title
        ttk.Label(self.root, text="IDS Dashboard", font=("Arial", 16)).pack(pady=10)

        # Buttons
        frame = ttk.Frame(self.root)
        frame.pack(pady=10)

        ttk.Button(frame, text="Start IDS", command=start_callback).pack(side="left", padx=10)
        ttk.Button(frame, text="Simulate Attack", command=attack_callback).pack(side="left", padx=10)

        # Treeview for alerts
        self.tree = ttk.Treeview(self.root, columns=("IP", "Reason", "Time"), show="headings")
        self.tree.heading("IP", text="Source IP")
        self.tree.heading("Reason", text="Alert Type")
        self.tree.heading("Time", text="Timestamp")
        self.tree.pack(expand=True, fill="both", padx=20, pady=10)

        self.counter_label = ttk.Label(self.root, text="Attack Counts: {}")
        self.counter_label.pack(pady=5)

        self.root.after(1000, self.check_alert_queue)

    def check_alert_queue(self):
        while not self.alert_queue.empty():
            ip, reason, timestamp = self.alert_queue.get()
            self.tree.insert("", "end", values=(ip, reason, timestamp))
            self.ip_counts[ip] = self.ip_counts.get(ip, 0) + 1
            self.counter_label.config(text=f"Attack Counts: {self.ip_counts}")
            messagebox.showwarning("⚠️ Intrusion Detected", f"{reason} from {ip}")
        self.root.after(1000, self.check_alert_queue)

    def show_alert(self, ip, reason):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alert_queue.put((ip, reason, timestamp))

    def run(self):
        self.root.mainloop()