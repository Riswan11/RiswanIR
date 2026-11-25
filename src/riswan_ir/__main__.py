"""Run the local Riswan IR server."""

from wsgiref.simple_server import make_server

from .api.http import Application
from .core.config import database_path, setting
from .storage.sqlite import Store


def main():
    port = int(setting("PORT") or "8000")
    store = Store(database_path())
    with make_server("127.0.0.1", port, Application(store)) as server:
        print(f"Riswan IR is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
