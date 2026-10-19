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


def test_returns_only_current_exclusions():
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
        ]
    )

    exclusions = CrossApprovalRequestUserCase(adapter).execute()

    assert [exclusion.id for exclusion in exclusions] == ["CVE-current"]
    adapter.get_cross_approval_requests.assert_called_once_with()


def test_parses_approved_exclusions_from_cross_approval_api_response():
    tomorrow = date.today() + timedelta(days=1)
    response = CrossApprovalRequestList.from_dict(
        {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 34,
                    "owner": "x86",
                    "status": "approved",
                    "exclusions": [
                        {
                            "exclusion_id": 586,
                            "id": "CVE-2005-2541",
                            "where": "all",
                            "create_date": "15102026",
                            "expired_date": tomorrow.strftime("%d%m%Y"),
                            "expired_at": None,
                            "priority": "",
                            "severity": "low,medium",
                            "hu": "7946061",
                            "reason": "base image vulnerability",
                            "cve_id": "CVE-2005-2541",
                            "component": {
                                "type": "image",
                                "values": ["registry.example/python:3.10-slim"],
                            },
                        }
                    ],
                }
            ],
        }
    )
    adapter = Mock()
    adapter.get_cross_approval_requests.return_value = response

    exclusions = CrossApprovalRequestUserCase(adapter).execute()

    assert len(exclusions) == 1
    assert exclusions[0].id == "CVE-2005-2541"
    assert exclusions[0].severity == "low,medium"
    assert exclusions[0].component.values == ["registry.example/python:3.10-slim"]


def test_does_not_filter_by_status_relies_on_server_side_filtering():
    """The REST consumer now requests only approved requests via the
    `status=approved` query param, so the use case no longer filters by
    status client-side and simply trusts whatever the server returns."""
    adapter = Mock()
    adapter.get_cross_approval_requests.return_value = CrossApprovalRequestList(
        results=[
            CrossApprovalRequest(
                status="pending",
                exclusions=[CrossApprovalExclusion(id="CVE-not-filtered")],
            ),
        ]
    )

    exclusions = CrossApprovalRequestUserCase(adapter).execute()

    assert [exclusion.id for exclusion in exclusions] == ["CVE-not-filtered"]


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