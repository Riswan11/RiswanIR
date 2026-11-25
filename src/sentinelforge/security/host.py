"""Limit the development HTTP interface to loopback Host headers."""

import re

LOCAL_HOST = re.compile(r"(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?", re.IGNORECASE | re.ASCII)


def is_local_host(value):
    return LOCAL_HOST.fullmatch(value) is not None
