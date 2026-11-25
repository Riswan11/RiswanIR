"""Trusted context provider for the explicitly configured workstation runtime."""

from uuid import UUID, uuid4

from riswan_platform.core.context import ActorType, PlatformContext
from riswan_platform.core.exceptions import ContextRequiredError

LOCAL_TENANT = UUID("046096a9-dbf1-4dc2-a1ef-d776a6477b28")


def local_context(
    mode: str | None, product_id: str, *, actor_type: ActorType = "human"
) -> PlatformContext:
    if mode != "local":
        raise ContextRequiredError("Set RISWAN_IR_MODE=local to run the workstation application.")
    request_id = uuid4().hex
    return PlatformContext(
        tenant_id=LOCAL_TENANT,
        actor_id="local-operator" if actor_type == "human" else "local-worker",
        actor_type=actor_type,
        product_id=product_id,
        request_id=request_id,
        correlation_id=request_id,
    )
