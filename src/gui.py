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
    """Scans user-defined port range and updates the GUI table in real-time with colors."""
    ip_address = resolve_target(target)
    if ip_address is None:
        messagebox.showerror("Error", f"Unable to resolve hostname: {target}")
        return 

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Reduce timeout for faster scanning
            result = s.connect_ex((ip_address, port))
            
            if result == 0:
                status = "OPEN"
                tag = "open"
            elif result == 10061:  # Windows-specific error for actively refused connections
                status = "CLOSED"
                tag = "closed"
            else:
                status = "FILTERED"
                tag = "filtered"

            # Insert row with color formatting
            row_id = tree.insert("", "end", values=(port, status))
            tree.item(row_id, tags=(tag,))

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
root.geometry("550x400")
root.configure(bg="#2C2F33")  # Darker background

# Apply modern styling
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#23272A", foreground="white", fieldbackground="#23272A")
style.map("Treeview", background=[("selected", "#7289DA")])

# Target Input
frame_top = tk.Frame(root, bg="#2C2F33")
frame_top.pack(pady=10)
tk.Label(frame_top, text="Target IP/Host:", fg="white", bg="#2C2F33").pack(side=tk.LEFT)
entry_target = tk.Entry(frame_top, width=25)
entry_target.pack(side=tk.LEFT, padx=5)

# Port Range Input with Up/Down Arrows
frame_ports = tk.Frame(root, bg="#2C2F33")
frame_ports.pack(pady=5)

def adjust_port(var, amount):
    """Adjusts the port number, keeping it in range 1-65535."""
    new_value = max(1, min(65535, var.get() + amount))
    var.set(new_value)

def hold_adjust(var, amount):
    """Rapidly increases/decreases the port number while button is held."""
    adjust_port(var, amount)
    root.after(100, hold_adjust, var, amount)  # Repeat every 100ms

# Start Port
tk.Label(frame_ports, text="Start Port:", fg="white", bg="#2C2F33").pack(side=tk.LEFT)
start_port_var = tk.IntVar(value=20)
entry_start_port = tk.Entry(frame_ports, textvariable=start_port_var, width=6)
entry_start_port.pack(side=tk.LEFT, padx=2)

btn_up_start = tk.Button(frame_ports, text="▲", width=2, command=lambda: adjust_port(start_port_var, 1))
btn_up_start.pack(side=tk.LEFT)
btn_down_start = tk.Button(frame_ports, text="▼", width=2, command=lambda: adjust_port(start_port_var, -1))
btn_down_start.pack(side=tk.LEFT)

# End Port
tk.Label(frame_ports, text="End Port:", fg="white", bg="#2C2F33").pack(side=tk.LEFT, padx=10)
end_port_var = tk.IntVar(value=25)
entry_end_port = tk.Entry(frame_ports, textvariable=end_port_var, width=6)
entry_end_port.pack(side=tk.LEFT, padx=2)

btn_up_end = tk.Button(frame_ports, text="▲", width=2, command=lambda: adjust_port(end_port_var, 1))
btn_up_end.pack(side=tk.LEFT)
btn_down_end = tk.Button(frame_ports, text="▼", width=2, command=lambda: adjust_port(end_port_var, -1))
btn_down_end.pack(side=tk.LEFT)

# Scan Button
tk.Button(root, text="Scan", command=start_scan, bg="#7289DA", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

# Results Table
tree = ttk.Treeview(root, columns=("Port", "Status"), show="headings", height=12)
tree.heading("Port", text="Port")
tree.heading("Status", text="Status")
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Define colors for open/closed/filtered ports
tree.tag_configure("open", foreground="green")
tree.tag_configure("closed", foreground="red")
tree.tag_configure("filtered", foreground="yellow")

root.mainloop()
