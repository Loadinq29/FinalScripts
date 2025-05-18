import tkinter as tk
from tkinter import filedialog, simpledialog
import hashlib
import psutil
import time
import threading
import os
import subprocess
import socket
from queue import Queue


# ------------------ New/Modified Functions ------------------

def check_autoruns():
    output = []
    try:
        reg_paths = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ]
        for path in reg_paths:
            result = subprocess.check_output(f'reg query "{path}"', shell=True, text=True)
            output.append(f"--- {path} ---\n{result}")
    except subprocess.CalledProcessError as e:
        output.append(f"[!] Failed to read registry: {e}")

    startup_dir = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.exists(startup_dir):
        files = os.listdir(startup_dir)
        output.append(f"\n--- Startup Folder ---\n" + "\n".join(files) if files else "\n--- Startup Folder ---\nNo files found.")
    else:
        output.append("\n[!] Startup folder not found.")
    output_results(output, "Autoruns / Persistence Check")


def check_active_connections():
    output = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            try:
                proc = psutil.Process(conn.pid)
                pname = proc.name()
            except:
                pname = "N/A"
            output.append(f"{pname} (PID: {conn.pid}) --> {conn.laddr.ip}:{conn.laddr.port} ↔ {conn.raddr.ip}:{conn.raddr.port}")
    output_results(output if output else ["No active network connections found."], "Active Network Connections")


def block_ips():
    ip_input = simpledialog.askstring("Block IPs", "Enter IPs to block (comma-separated):")
    if not ip_input:
        output_results(["[!] No IPs provided."], "Firewall Rule")
        return

    bad_ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
    results = []

    for ip in bad_ips:
        for direction in ['Inbound', 'Outbound']:
            try:
                subprocess.run([
                    "powershell",
                    f"New-NetFirewallRule -DisplayName 'Block {direction} {ip}' "
                    f"-Direction {direction} -RemoteAddress {ip} -Action Block "
                    f"-Profile Any -Enabled True"
                ], check=True)
                results.append(f"[+] Blocked {direction} traffic to/from IP: {ip}")
            except subprocess.CalledProcessError:
                results.append(f"[!] Failed to block {direction} IP: {ip}")

    output_results(results, "Firewall Rule")


def disconnect_by_pid():
    try:
        pid = int(simpledialog.askstring("Disconnect Connection", "Enter the PID of the process to terminate:"))
    except (TypeError, ValueError):
        output_results(["[!] Invalid PID input."], "Disconnect")
        return

    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        proc.wait(timeout=3)
        output_results([f"[+] Terminated {name} (PID: {pid})"], "Disconnect")
    except psutil.NoSuchProcess:
        output_results([f"[!] No process found with PID {pid}"], "Disconnect")
    except Exception as e:
        output_results([f"[!] Failed to terminate PID {pid}: {e}"], "Disconnect")


# ------------------ Utilities ------------------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def monitor_files(files):
    file_hashes = {f: get_sha256(f) for f in files}
    output_results([f"[+] Monitoring {len(files)} files for changes..."], "File Integrity")

    def watcher():
        while True:
            for f, old_hash in file_hashes.items():
                try:
                    new_hash = get_sha256(f)
                    if new_hash != old_hash:
                        output_results([f"[!] Change detected in: {f}"], "File Integrity")
                        file_hashes[f] = new_hash
                except:
                    output_results([f"[!] File missing or inaccessible: {f}"], "File Integrity")
            time.sleep(15)

    threading.Thread(target=watcher, daemon=True).start()


def scan_ports_gui():
    t_ip = get_local_ip()
    result_text.insert(tk.END, f"\n[+] Detected Local IP: {t_ip}\n")
    try:
        port_start = int(simpledialog.askstring("Port Scan", "Enter start port:", initialvalue="20"))
        port_stop = int(simpledialog.askstring("Port Scan", "Enter end port:", initialvalue="1024"))
    except (ValueError, TypeError):
        output_results(["[!] Invalid port range"], "Port Scanner")
        return

    socket.setdefaulttimeout(0.55)
    thread_lock = threading.Lock()
    q = Queue()
    open_ports = []

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.55)
        try:
            s.connect((t_ip, port))
            s.close()
            with thread_lock:
                open_ports.append(port)
        except:
            pass

    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    for _ in range(200):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(port_start, port_stop + 1):
        q.put(worker)

    start_time = time.time()
    q.join()
    elapsed = time.time() - start_time

    results = [f"Port {p} is OPEN" for p in sorted(open_ports)]
    results.append(f"\nRun Time: {elapsed:.2f} seconds")
    output_results(results, "Port Scanner")


# ------------------ GUI Setup ------------------

def output_results(messages, title="Results"):
    result_text.insert(tk.END, f"\n--- {title} ---\n")
    for msg in messages:
        result_text.insert(tk.END, msg + "\n")
    result_text.insert(tk.END, "-" * 50 + "\n")
    result_text.see(tk.END)


def start_file_monitor():
    files = filedialog.askopenfilenames(title="Select Files to Monitor")
    if files:
        monitor_files(files)


root = tk.Tk()
root.title("Windows Cyber Defense Toolkit")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

tk.Label(frame, text="Select a Defense Operation:", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=10)

tk.Button(frame, text="1. Run Port Scanner (Auto-Detect IP)", width=35, command=scan_ports_gui).grid(row=1, column=0, pady=5)
tk.Button(frame, text="2. Block IPs (Custom Input)", width=35, command=block_ips).grid(row=2, column=0, pady=5)
tk.Button(frame, text="3. Disconnect Active Connection by PID", width=35, command=disconnect_by_pid).grid(row=3, column=0, pady=5)
tk.Button(frame, text="4. Monitor File Integrity", width=35, command=start_file_monitor).grid(row=4, column=0, pady=5)
tk.Button(frame, text="5. Check Autoruns / Persistence", width=35, command=check_autoruns).grid(row=5, column=0, pady=5)
tk.Button(frame, text="6. Show Active Network Connections", width=35, command=check_active_connections).grid(row=6, column=0, pady=5)


result_text = tk.Text(root, height=20, width=80, bg="black", fg="lime", font=("Courier", 10))
result_text.pack(padx=10, pady=10)

root.mainloop()
