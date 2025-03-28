import socket
import tkinter as tk
from tkinter import ttk, messagebox
import threading

def resolve_target(target):
    """Resolve a hostname to an IP address or return None if it fails."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def scan_ports(target, start_port, end_port, tree):
    """Scans user-defined port range and updates the GUI table in real-time."""
    ip_address = resolve_target(target)
    if ip_address is None:
        messagebox.showerror("Error", f"Unable to resolve hostname: {target}")
        return 

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Reduce timeout for faster scanning
            result = s.connect_ex((ip_address, port))
            status = "OPEN" if result == 0 else "CLOSED"
            tree.insert("", "end", values=(port, status))

def start_scan():
    """Gets target and port range, then starts a threaded scan."""
    target = entry_target.get().strip()
    start_port = start_port_var.get()
    end_port = end_port_var.get()

    if not target:
        messagebox.showwarning("Warning", "Please enter a target IP or hostname.")
        return
    
    if start_port > end_port:
        messagebox.showwarning("Warning", "Start port must be ≤ end port.")
        return

    tree.delete(*tree.get_children())  # Clear previous results
    threading.Thread(target=scan_ports, args=(target, start_port, end_port, tree), daemon=True).start()

# Initialize GUI
root = tk.Tk()
root.title("SecurePort Scanner")
root.geometry("500x350")

# Target Input
frame_top = tk.Frame(root)
frame_top.pack(pady=10)
tk.Label(frame_top, text="Target IP/Host:").pack(side=tk.LEFT)
entry_target = tk.Entry(frame_top, width=20)
entry_target.pack(side=tk.LEFT, padx=5)

# Port Range Input with Up/Down Arrows
frame_ports = tk.Frame(root)
frame_ports.pack(pady=5)

def adjust_port(var, amount):
    """Adjusts the port number, keeping it in range 1-65535."""
    new_value = max(1, min(65535, var.get() + amount))
    var.set(new_value)

# Start Port
tk.Label(frame_ports, text="Start Port:").pack(side=tk.LEFT)
start_port_var = tk.IntVar(value=20)  # Default start port
entry_start_port = tk.Entry(frame_ports, textvariable=start_port_var, width=5)
entry_start_port.pack(side=tk.LEFT, padx=2)
tk.Button(frame_ports, text="▲", command=lambda: adjust_port(start_port_var, 1)).pack(side=tk.LEFT)
tk.Button(frame_ports, text="▼", command=lambda: adjust_port(start_port_var, -1)).pack(side=tk.LEFT)

# End Port
tk.Label(frame_ports, text="End Port:").pack(side=tk.LEFT, padx=5)
end_port_var = tk.IntVar(value=25)  # Default end port
entry_end_port = tk.Entry(frame_ports, textvariable=end_port_var, width=5)
entry_end_port.pack(side=tk.LEFT, padx=2)
tk.Button(frame_ports, text="▲", command=lambda: adjust_port(end_port_var, 1)).pack(side=tk.LEFT)
tk.Button(frame_ports, text="▼", command=lambda: adjust_port(end_port_var, -1)).pack(side=tk.LEFT)

# Scan Button
tk.Button(root, text="Scan", command=start_scan).pack(pady=10)

# Results Table
tree = ttk.Treeview(root, columns=("Port", "Status"), show="headings")
tree.heading("Port", text="Port")
tree.heading("Status", text="Status")
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()
