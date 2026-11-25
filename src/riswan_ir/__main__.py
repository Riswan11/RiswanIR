"""Run the local Riswan IR server."""

from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

from riswan_app.composition import compose_local
from riswan_app.identity_runtime import compose_identity
from riswan_platform.core.exceptions import ContextRequiredError

from .core.config import database_path, setting


class IdentityRequestHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        # WSGI's default access log includes the OAuth callback query string.
        return


def main(*, local_launcher: bool = False):
    port = int(setting("PORT") or "8000")
    mode = setting("MODE")
    if mode == "oidc":
        config, identity_db = setting("OIDC_CONFIG"), setting("IDENTITY_DB")
        if not config or not identity_db:
            raise SystemExit("Set RISWAN_IR_OIDC_CONFIG and RISWAN_IR_IDENTITY_DB.")
        try:
            application = compose_identity(Path(config), Path(identity_db), Path(database_path()))
        except (ValueError, OSError):
            raise SystemExit("Invalid identity runtime configuration.") from None
        with make_server(
            "127.0.0.1", port, application, handler_class=IdentityRequestHandler
        ) as server:
            server.serve_forever()
        return
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
