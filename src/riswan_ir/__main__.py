"""Run the local Riswan IR server."""

from wsgiref.simple_server import make_server

from riswan_app.composition import compose_local
from riswan_platform.core.exceptions import ContextRequiredError

from .core.config import database_path, setting


def main(*, local_launcher: bool = False):
    port = int(setting("PORT") or "8000")
    mode = setting("MODE")
    try:
        runtime = compose_local(
            database_path(), "local" if local_launcher and mode is None else mode
        )
    except ContextRequiredError as exc:
        raise SystemExit(str(exc)) from None
    with make_server("127.0.0.1", port, runtime.http) as server:
        print(f"Riswan IR is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
