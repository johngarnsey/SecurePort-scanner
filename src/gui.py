import socket
import tkinter as tk
from tkinter import ttk, messagebox
import threading

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def scan_ports(target, start_port, end_port, tree, progress, progress_max):
    ip_address = resolve_target(target)
    if ip_address is None:
        messagebox.showerror("Error", f"Unable to resolve hostname: {target}")
        return

    scanned = 0
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip_address, port))

            if result == 0:
                status = "OPEN"
                tag = "open"
            elif result == 10061:
                status = "CLOSED"
                tag = "closed"
            else:
                status = "FILTERED"
                tag = "filtered"

            row_id = tree.insert("", "end", values=(port, status))
            tree.item(row_id, tags=(tag,))

        scanned += 1
        percent = int((scanned / total_ports) * 100)
        progress["value"] = percent
        progress.update_idletasks()

def start_scan():
    target = entry_target.get().strip()
    start_port = start_port_var.get()
    end_port = end_port_var.get()

    if not target:
        messagebox.showwarning("Warning", "Please enter a target IP or hostname.")
        return
    if start_port > end_port:
        messagebox.showwarning("Warning", "Start port must be ≤ end port.")
        return

    tree.delete(*tree.get_children())
    progress_bar["value"] = 0
    progress_bar["maximum"] = 100

    threading.Thread(target=scan_ports, args=(target, start_port, end_port, tree, progress_bar, 100), daemon=True).start()

root = tk.Tk()
root.title("SecurePort Scanner")
root.geometry("600x400")
root.configure(bg="#2C2F33")

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

# Port Range Input
frame_ports = tk.Frame(root, bg="#2C2F33")
frame_ports.pack(pady=5)

def adjust_port(var, amount):
    new_value = max(1, min(65535, var.get() + amount))
    var.set(new_value)

# Start Port
tk.Label(frame_ports, text="Start Port:", fg="white", bg="#2C2F33").pack(side=tk.LEFT)
start_port_var = tk.IntVar(value=20)
entry_start_port = tk.Entry(frame_ports, textvariable=start_port_var, width=6)
entry_start_port.pack(side=tk.LEFT, padx=2)
tk.Button(frame_ports, text="▲", width=2, command=lambda: adjust_port(start_port_var, 1)).pack(side=tk.LEFT)
tk.Button(frame_ports, text="▼", width=2, command=lambda: adjust_port(start_port_var, -1)).pack(side=tk.LEFT)

# End Port
tk.Label(frame_ports, text="End Port:", fg="white", bg="#2C2F33").pack(side=tk.LEFT, padx=10)
end_port_var = tk.IntVar(value=25)
entry_end_port = tk.Entry(frame_ports, textvariable=end_port_var, width=6)
entry_end_port.pack(side=tk.LEFT, padx=2)
tk.Button(frame_ports, text="▲", width=2, command=lambda: adjust_port(end_port_var, 1)).pack(side=tk.LEFT)
tk.Button(frame_ports, text="▼", width=2, command=lambda: adjust_port(end_port_var, -1)).pack(side=tk.LEFT)

# Scan Button
tk.Button(root, text="Scan", command=start_scan, bg="#7289DA", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

# Frame for tree and vertical progress bar
frame_main = tk.Frame(root, bg="#2C2F33")
frame_main.pack(fill=tk.BOTH, expand=True, padx=10)

# Treeview for port results
tree = ttk.Treeview(frame_main, columns=("Port", "Status"), show="headings", height=12)
tree.heading("Port", text="Port")
tree.heading("Status", text="Status")
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

tree.tag_configure("open", foreground="green")
tree.tag_configure("closed", foreground="red")
tree.tag_configure("filtered", foreground="purple")

# Vertical Progress Bar (styled like a filling cup)
progress_bar_style = ttk.Style()
progress_bar_style.theme_use("default")
progress_bar_style.configure("Vertical.TProgressbar", thickness=20, troughcolor="#1E2124", background="#00FFAA")

progress_bar = ttk.Progressbar(frame_main, orient="vertical", mode="determinate", length=220, style="Vertical.TProgressbar")
progress_bar.pack(side=tk.RIGHT, padx=10, pady=5)

root.mainloop()
