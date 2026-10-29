# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
HTTP test server for serving local files during tests.

This module provides a local HTTP server that can be used in pytest fixtures
to serve files from a specified directory. The server runs on a random port
and supports both IPv4 and IPv6.

The server is commonly used for testing:
- Mock conda channels with packages and repodata
- Remote environment files (environment.yml)
- Remote configuration files
- Any scenario where conda needs to fetch files from HTTP URLs

Example usage:

    from conda.testing import http_test_server

    def test_something():
        server = http_test_server.run_test_server("/path/to/files")
        host, port = server.socket.getsockname()[:2]
        url = f"http://{host}:{port}/file.txt"

        # Make HTTP requests to url...

        server.shutdown()

Pass ``enable_auth=True`` to reject requests that don't authenticate with either
basic auth (``AUTH_USER``/``AUTH_PASSWORD``) or an anaconda.org style
``/t/<AUTH_TOKEN>/`` URL prefix.

For pytest fixtures that wrap this functionality, see:
- `http_test_server` - function-scoped fixture

The fixture can be configured via `@pytest.mark.parametrize("http_test_server", ["<directory>"], indirect=True)`
to specify the directory to serve, or used without parametrize (or with `None`) for dynamic content generation.
"""

import base64
from collections.abc import Callable
from contextlib import suppress
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from queue import Queue
from socket import IPPROTO_IPV6, IPV6_V6ONLY
from threading import Thread

AUTH_USER = "conda-user"
AUTH_PASSWORD = "conda-password"
AUTH_TOKEN = "xx-00000000-0000-0000-0000-000000000000"


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Reject requests without basic auth or a ``/t/<token>/`` prefix with a 401."""

    basic_auth = base64.b64encode(f"{AUTH_USER}:{AUTH_PASSWORD}".encode()).decode()
    token_prefix = f"/t/{AUTH_TOKEN}"

    def _authorized(self) -> bool:
        if self.path.startswith(f"{self.token_prefix}/"):
            self.path = self.path[len(self.token_prefix) :]
            return True
        return self.headers.get("Authorization") == f"Basic {self.basic_auth}"

    def do_HEAD(self):
        if self._authorized():
            return super().do_HEAD()
        self.send_error(401)

    def do_GET(self):
        if self._authorized():
            return super().do_GET()
        self.send_error(401)


def run_test_server(
    directory: str,
    finish_request_action: Callable[[], None] | None = None,
    enable_auth: bool = False,
) -> ThreadingHTTPServer:
    """
    Run a test server on a random port. Inspect returned server to get port,
    shutdown etc.

    Args:
        directory: Directory to serve files from.
        finish_request_action: Optional callable invoked before each request is
            handled (e.g. to inject latency or failures).
        enable_auth: Require basic auth or a ``/t/<token>/`` prefix on every request,
            see ``AuthHTTPRequestHandler``.
    """
    handler = AuthHTTPRequestHandler if enable_auth else SimpleHTTPRequestHandler

    class DualStackServer(ThreadingHTTPServer):
        daemon_threads = False  # These are per-request threads
        allow_reuse_address = True  # Good for tests
        request_queue_size = 64  # Should be more than the number of test packages

        def server_bind(self):
            # suppress exception when protocol is IPv4
            with suppress(Exception):
                self.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            return super().server_bind()

        def finish_request(self, request, client_address):
            if finish_request_action:
                finish_request_action()
            super().finish_request(request, client_address)

    def start_server(queue):
        try:
            with DualStackServer(
                ("127.0.0.1", 0),
                partial(handler, directory=directory),
            ) as httpd:
                host, port = httpd.socket.getsockname()[:2]
                queue.put(httpd)
                url_host = f"[{host}]" if ":" in host else host
                print(
                    f"Serving HTTP on {host} port {port} (http://{url_host}:{port}/) ..."
                )
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print("\nKeyboard interrupt received, exiting.")
        except Exception as exc:
            queue.put(exc)

    started: Queue[ThreadingHTTPServer | Exception] = Queue()

    Thread(target=start_server, args=(started,), daemon=True).start()

    result = started.get(timeout=1)
    if isinstance(result, Exception):
        raise result
    return result


if __name__ == "__main__":
    server = run_test_server(directory=".")
    print(server)
