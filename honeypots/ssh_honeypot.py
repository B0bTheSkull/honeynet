"""SSH honeypot using paramiko."""
import socket
import threading
import paramiko
import logging

# Suppress paramiko's own logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class FakeSSHServer(paramiko.ServerInterface):
    """Fake SSH server that accepts all credentials and logs them."""

    def __init__(self, logger, source_ip, source_port):
        self.logger = logger
        self.source_ip = source_ip
        self.source_port = source_port
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.logger.log(
            honeypot_type="SSH",
            source_ip=self.source_ip,
            source_port=self.source_port,
            event_type="login_attempt",
            details={"username": username, "password": password, "method": "password"}
        )
        # Accept first attempt to see what they do next, then hang/disconnect
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.logger.log(
            honeypot_type="SSH",
            source_ip=self.source_ip,
            source_port=self.source_port,
            event_type="login_attempt",
            details={"username": username, "method": "publickey", "key_type": key.get_name()}
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", errors="replace")
        self.logger.log(
            honeypot_type="SSH",
            source_ip=self.source_ip,
            source_port=self.source_port,
            event_type="command_exec",
            details={"command": cmd}
        )
        channel.send(b"bash: command not found\n")
        channel.send_exit_status(127)
        return True


def _handle_client(client_sock, addr, server_key, logger, banner):
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = banner
        transport.add_server_key(server_key)

        server = FakeSSHServer(logger, addr[0], addr[1])
        transport.start_server(server=server)

        chan = transport.accept(30)
        if chan is None:
            return

        # Fake shell — log commands and send fake prompt
        fake_prompt = b"root@ubuntu:~# "
        chan.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
        chan.send(fake_prompt)

        buf = b""
        chan.settimeout(60)
        while True:
            try:
                data = chan.recv(1024)
                if not data:
                    break
                chan.send(data)  # Echo input
                buf += data
                if b"\r" in buf or b"\n" in buf:
                    command = buf.decode("utf-8", errors="replace").strip()
                    if command:
                        logger.log(
                            honeypot_type="SSH",
                            source_ip=addr[0],
                            source_port=addr[1],
                            event_type="shell_command",
                            details={"command": command}
                        )
                    chan.send(b"\r\nbash: " + command.encode() + b": command not found\r\n")
                    chan.send(fake_prompt)
                    buf = b""
            except socket.timeout:
                break
            except Exception:
                break

    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


class SSHHoneypot:
    def __init__(self, port, logger, banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"):
        self.port = port
        self.logger = logger
        self.banner = banner
        self.server_key = paramiko.RSAKey.generate(2048)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(50)

        while True:
            try:
                client, addr = sock.accept()
                self.logger.log("SSH", addr[0], addr[1], "connection", {"port": self.port})
                t = threading.Thread(
                    target=_handle_client,
                    args=(client, addr, self.server_key, self.logger, self.banner),
                    daemon=True
                )
                t.start()
            except Exception:
                break
