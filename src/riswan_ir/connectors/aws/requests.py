"""Bound, pace, and retry individual AWS requests without exposing SDK errors."""

import random
import time
from collections.abc import Callable
from typing import TypeVar

from botocore.exceptions import BotoCoreError, ClientError, ConnectionError, HTTPClientError

from ..base import CollectionFailure

T = TypeVar("T")
RETRYABLE = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "SlowDown",
    "ServiceUnavailable",
    "InternalError",
    "InternalFailure",
    "RequestTimeout",
}
AUTH_ERRORS = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
}
LAST_REGIONAL_CALL: dict[tuple[str, str], float] = {}


class RequestBudget:
    def __init__(
        self,
        limit: int,
        pause: Callable[[float], None] = time.sleep,
        check: Callable[[], None] | None = None,
    ) -> None:
        self.limit = limit
        self.pause = pause
        self.used = 0
        self.check = check

    def call(
        self,
        operation: str,
        invoke: Callable[[], T],
        *,
        regional_limit: tuple[str, str] | None = None,
    ) -> T:
        for attempt in range(4):
            if self.used >= self.limit:
                raise CollectionFailure(operation, "request_budget_exceeded")
            if regional_limit is not None:
                previous = LAST_REGIONAL_CALL.get(regional_limit)
                if previous is not None:
                    self.pause(max(0, 0.51 - (time.monotonic() - previous)))
                LAST_REGIONAL_CALL[regional_limit] = time.monotonic()
            if self.check is not None:
                self.check()
            self.used += 1
            try:
                result = invoke()
                if self.check is not None:
                    self.check()
                return result
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
                if code in AUTH_ERRORS or status in (401, 403):
                    raise CollectionFailure(
                        operation,
                        "credentials_expired"
                        if code in ("ExpiredToken", "ExpiredTokenException")
                        else "access_denied",
                    ) from None
                if code not in RETRYABLE and status not in (429, 500, 502, 503, 504):
                    raise CollectionFailure(operation, "aws_request_failed") from None
            except (ConnectionError, HTTPClientError):
                pass
            except BotoCoreError:
                raise CollectionFailure(operation, "sdk_error") from None
            if attempt < 3:
                self.pause(0.5 * (2**attempt) + random.uniform(0, 0.2))  # nosec B311
        raise CollectionFailure(operation, "retry_limit_exceeded")
