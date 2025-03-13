import tkinter as tk
from tkinter import ttk
import threading
import socket

def scan_ports(target, port_list, tree):
    """Scans ports and updates the GUI table in real-time."""
    for port in port_list:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Reduce timeout for faster scanning
            result = s.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
            tree.insert("", "end", values=(port, status))

def start_scan():
    """Gets target and starts a threaded scan."""
    target = entry_target.get().strip()
    if not target:
        return
    tree.delete(*tree.get_children())  # Clear previous results
    port_list = range(20, 30)  # Example range for testing
    threading.Thread(target=scan_ports, args=(target, port_list, tree), daemon=True).start()

# Initialize GUI
root = tk.Tk()
root.title("SecurePort Scanner")
root.geometry("400x300")

# Target Input
frame_top = tk.Frame(root)
frame_top.pack(pady=10)
tk.Label(frame_top, text="Target IP/Host:").pack(side=tk.LEFT)
entry_target = tk.Entry(frame_top)
entry_target.pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="Scan", command=start_scan).pack(side=tk.LEFT)

# Results Table
tree = ttk.Treeview(root, columns=("Port", "Status"), show="headings")
tree.heading("Port", text="Port")
tree.heading("Status", text="Status")
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()
