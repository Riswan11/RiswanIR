"""Organization API inputs use bounded tenant-management contracts."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from riswan_platform.tenancy import Acceptance, InvitationRequest, MembershipRole, OrganizationInput


def test_organization_defaults_and_lifecycle_payload_separation():
    organization = OrganizationInput(name="  Research  ")
    assert organization.name == "Research"
    assert organization.settings.description == ""
    with pytest.raises(ValidationError):
        OrganizationInput.model_validate({"name": "Research", "status": "active"})


def test_tenancy_mutations_validate_identity_and_token_types():
    identity = uuid4()
    invitation = InvitationRequest.model_validate({"identity_id": str(identity), "role": "viewer"})
    assert invitation.identity_id == identity
    assert invitation.role is MembershipRole.VIEWER
    with pytest.raises(ValidationError):
        InvitationRequest.model_validate({"identity_id": "other-actor", "role": "viewer"})
    with pytest.raises(ValidationError):
        Acceptance.model_validate({"token": "/" * 43})
