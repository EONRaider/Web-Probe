import pytest
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler


class TestingHTTPServer(HTTPServer):
    def run(self):
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.server_close()


@pytest.fixture
def http_server():
    host, port = '127.0.0.1', 8000
    server = TestingHTTPServer((host, port), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    yield
    server.shutdown()
    thread.join()
