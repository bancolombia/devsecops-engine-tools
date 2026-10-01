from datetime import date, timedelta
from unittest.mock import Mock

from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cross_approval_request import (
    CrossApprovalExclusion,
    CrossApprovalRequest,
    CrossApprovalRequestList,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.cross_approval_request import (
    CrossApprovalRequestUserCase,
)


def test_returns_only_approved_and_current_exclusions():
    tomorrow = date.today() + timedelta(days=1)
    yesterday = date.today() - timedelta(days=1)
    adapter = Mock()
    adapter.get_cross_approval_requests.return_value = CrossApprovalRequestList(
        results=[
            CrossApprovalRequest(
                status="approved",
                exclusions=[
                    CrossApprovalExclusion(id="CVE-current", expired_date=tomorrow.strftime("%d%m%Y")),
                    CrossApprovalExclusion(id="CVE-expired", expired_date=yesterday.strftime("%d%m%Y")),
                    CrossApprovalExclusion(id="CVE-expired-at", expired_at="2026-09-30T00:00:00Z"),
                ],
            ),
            CrossApprovalRequest(
                status="pending",
                exclusions=[CrossApprovalExclusion(id="CVE-pending")],
            ),
        ]
    )

    exclusions = CrossApprovalRequestUserCase(adapter).execute("https://dojo.example/crossapproval_requests/")

    assert [exclusion.id for exclusion in exclusions] == ["CVE-current"]


def test_invalid_expiration_date_is_not_accepted():
    assert CrossApprovalRequestUserCase._is_current(None, "not-a-date") is False


def test_parses_component_type_and_values_array():
    exclusion = CrossApprovalExclusion.from_dict(
        {
            "id": "CVE-2026-15157",
            "component": {
                "type": "image",
                "values": [
                    "registry.example/node:24-builder",
                    "registry.example/node:24-alpine",
                ],
            },
        }
    )

    assert exclusion.component.type == "image"
    assert exclusion.component.values == [
        "registry.example/node:24-builder",
        "registry.example/node:24-alpine",
    ]