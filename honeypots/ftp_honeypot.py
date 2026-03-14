"""FTP honeypot — socket-based fake FTP server."""
import socket
import threading


FAKE_FILES = [
    "drwxr-xr-x 2 root root 4096 Jan 15 03:22 .",
    "drwxr-xr-x 8 root root 4096 Jan 15 03:22 ..",
    "-rw-r--r-- 1 root root 2048 Jan 14 12:00 users.csv",
    "-rw-r--r-- 1 root root 8192 Jan 14 11:30 backup_2024.tar.gz",
    "-rw-r--r-- 1 root root 1024 Jan 13 09:15 config.bak",
]


def _handle_client(conn, addr, logger, banner):
    username = None
    try:
        conn.send(f"{banner}\r\n".encode())

        buf = ""
        while True:
            try:
                data = conn.recv(1024).decode("utf-8", errors="replace")
            except Exception:
                break
            if not data:
                break

            buf += data
            while "\r\n" in buf or "\n" in buf:
                line, _, buf = buf.partition("\r\n") if "\r\n" in buf else buf.partition("\n")
                line = line.strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    username = arg
                    conn.send(f"331 Password required for {username}\r\n".encode())

                elif cmd == "PASS":
                    password = arg
                    logger.log("FTP", addr[0], addr[1], "login_attempt",
                               {"username": username, "password": password})
                    conn.send(b"230 Login successful\r\n")

                elif cmd == "SYST":
                    conn.send(b"215 UNIX Type: L8\r\n")

                elif cmd == "PWD":
                    conn.send(b'257 "/" is current directory\r\n')

                elif cmd == "LIST" or cmd == "NLST":
                    logger.log("FTP", addr[0], addr[1], "directory_list", {"command": cmd, "arg": arg})
                    conn.send(b"150 Here comes the directory listing\r\n")
                    conn.send(("\r\n".join(FAKE_FILES) + "\r\n").encode())
                    conn.send(b"226 Directory send OK\r\n")

                elif cmd == "RETR":
                    filename = arg
                    logger.log("FTP", addr[0], addr[1], "file_download_attempt", {"filename": filename})
                    conn.send(b"550 Failed to open file\r\n")

                elif cmd == "STOR":
                    filename = arg
                    logger.log("FTP", addr[0], addr[1], "file_upload_attempt", {"filename": filename})
                    conn.send(b"550 Permission denied\r\n")

                elif cmd in ("QUIT", "BYE"):
                    conn.send(b"221 Goodbye\r\n")
                    return

                elif cmd == "PASV":
                    conn.send(b"227 Entering Passive Mode (127,0,0,1,195,149)\r\n")

                elif cmd == "TYPE":
                    conn.send(b"200 Type set\r\n")

                elif cmd == "FEAT":
                    conn.send(b"211 Features:\r\n UTF8\r\n211 End\r\n")

                elif cmd == "NOOP":
                    conn.send(b"200 NOOP ok\r\n")

                else:
                    logger.log("FTP", addr[0], addr[1], "unknown_command",
                               {"command": cmd, "arg": arg})
                    conn.send(f"500 Unknown command: {cmd}\r\n".encode())

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class FTPHoneypot:
    def __init__(self, port, logger, banner="220 FTP Server Ready"):
        self.port = port
        self.logger = logger
        self.banner = banner

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(50)

        while True:
            try:
                conn, addr = sock.accept()
                self.logger.log("FTP", addr[0], addr[1], "connection", {"port": self.port})
                t = threading.Thread(
                    target=_handle_client,
                    args=(conn, addr, self.logger, self.banner),
                    daemon=True
                )
                t.start()
            except Exception:
                break
