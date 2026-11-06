import socket
import ssl
import threading

import pytest

from crystalline_pki.app import App


@pytest.fixture
def app(tmp_path):
    instance = App(str(tmp_path / "home"))
    instance.config.set("rsa_bits", 2048)
    yield instance
    instance.close()


@pytest.fixture
def ready(app):
    app.pki.generate()
    return app


class LocalHTTPS:
    def __init__(self, app, headers=None, status="200 OK"):
        self.app = app
        self.headers = headers or []
        self.status = status
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(app.workspace.server_chain), str(app.workspace.server_key))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    data = tls.recv(4096)
                    if data:
                        self.requests.append(data.decode("latin-1"))
                        lines = ["HTTP/1.1 " + self.status, "Content-Length: 0", "Connection: close"] + self.headers
                        tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self.sock.close()


@pytest.fixture
def local_https(ready):
    servers = []

    def make(**kwargs):
        server = LocalHTTPS(ready, **kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def resolver(host):
    return ["127.0.0.1"]
