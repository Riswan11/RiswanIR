"""Run the local SentinelForge server."""

import os
from wsgiref.simple_server import make_server

from .api.http import Application
from .storage.sqlite import Store


def main():
    port = int(os.environ.get("SENTINELFORGE_PORT", "8000"))
    store = Store(os.environ.get("SENTINELFORGE_DB", "sentinelforge.sqlite3"))
    with make_server("127.0.0.1", port, Application(store)) as server:
        print(f"SentinelForge is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
