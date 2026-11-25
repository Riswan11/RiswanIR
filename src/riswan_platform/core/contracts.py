"""Published product and context-provider contracts."""

from typing import Protocol

from .context import PlatformContext


class ProductModule(Protocol):
    @property
    def product_id(self) -> str: ...
    @property
    def display_name(self) -> str: ...
    @property
    def version(self) -> str: ...
    def capabilities(self) -> tuple[str, ...]: ...


class ContextProvider(Protocol):
    def __call__(self) -> PlatformContext: ...
