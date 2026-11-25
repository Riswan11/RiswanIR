"""Run the local TrailHound server."""

from wsgiref.simple_server import make_server

from .api.http import Application
from .core.config import database_path, server_port
from .storage.sqlite import Store


def main():
    port = server_port()
    store = Store(str(database_path()))
    with make_server("127.0.0.1", port, Application(store)) as server:
        print(f"TrailHound is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
