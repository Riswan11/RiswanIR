"""Shared model validation and serialization."""

from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

from .time import utc_timestamp

Text = Annotated[str, StringConstraints(min_length=1, max_length=300, strip_whitespace=True)]


def validate_timestamp(value: str) -> str:
    utc_timestamp(value)
    return value


Timestamp = Annotated[str, AfterValidator(validate_timestamp)]


class DomainModel(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    def payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)
