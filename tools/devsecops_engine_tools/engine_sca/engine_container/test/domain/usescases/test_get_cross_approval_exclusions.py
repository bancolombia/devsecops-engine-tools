from unittest.mock import Mock

import pytest

from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.get_cross_approval_exclusions import (
    GetCrossApprovalExclusions,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cross_approval_request import (
    CrossApprovalExclusion,
)


def test_disabled_feature_does_not_call_gateway():
    gateway = Mock()

    result = GetCrossApprovalExclusions(gateway).execute(
        {"CROSS_APPROVAL_EXCLUSIONS": {"ENABLED": False}}, {}, {}
    )

    assert result == []
    gateway.get_approved_exclusions.assert_not_called()


def test_maps_exclusions_and_uses_available_defect_dojo_token():
    gateway = Mock()
    gateway.get_approved_exclusions.return_value = [
        CrossApprovalExclusion(
            id="CVE-2026-1000",
            where="all",
            create_date="01092026",
            expired_date="01102026",
            priority="high",
            hu="12345",
            reason="Approved exception",
            cve_id="CVE-2026-1000",
            component=Mock(type="image", values=["registry.example/node:24"]),
        )
    ]

    result = GetCrossApprovalExclusions(gateway).execute(
        {"CROSS_APPROVAL_EXCLUSIONS": {"ENABLED": True, "URL": "https://dojo.example/api/v2/crossapproval_requests/"}},
        {},
        {"token_defect_dojo": "dojo-token"},
    )

    gateway.get_approved_exclusions.assert_called_once_with(
        "https://dojo.example/api/v2/crossapproval_requests/", "dojo-token"
    )
    assert len(result) == 1
    assert result[0].id == "CVE-2026-1000"
    assert result[0].priority == "high"
    assert result[0].reason == "Approved exception"
    assert result[0].check_in_desc == ["registry.example/node:24"]


def test_ignores_non_image_components():
    gateway = Mock()
    gateway.get_approved_exclusions.return_value = [
        CrossApprovalExclusion(
            id="CVE-2026-1000",
            component=Mock(type="OpenSSL", values=["/usr/lib/libssl.so"]),
        )
    ]

    result = GetCrossApprovalExclusions(gateway).execute(
        {"CROSS_APPROVAL_EXCLUSIONS": {"ENABLED": True, "URL": "https://dojo.example/api/"}},
        {},
        {"token_defect_dojo": "dojo-token"},
    )

    assert result == []


def test_enabled_feature_requires_endpoint_url():
    gateway = Mock()

    with pytest.raises(ValueError, match="URL is not configured"):
        GetCrossApprovalExclusions(gateway).execute(
            {"CROSS_APPROVAL_EXCLUSIONS": {"ENABLED": True}}, {}, {}
        )