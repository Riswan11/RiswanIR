"""Errors shared across application boundaries."""


class NotFoundError(LookupError):
    pass


class ContextRequiredError(PermissionError):
    pass
