from unittest.mock import Mock

from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.cross_approval_request import (
    CrossApprovalRequestRestConsumer,
)


def test_get_cross_approval_requests_follows_next_page():
    session = Mock()
    session._token = "token"
    session._host = "https://dojo.example"
    session._instance = Mock()
    first_page = Mock(status_code=200)
    first_page.json.return_value = {
        "count": 2,
        "next": "https://dojo.example/api/v2/crossapproval_requests/?status=approved&page=2",
        "results": [{"status": "approved", "exclusions": [{"id": "CVE-1"}]}],
    }
    second_page = Mock(status_code=200)
    second_page.json.return_value = {
        "count": 2,
        "next": None,
        "results": [{"status": "approved", "exclusions": [{"id": "CVE-2"}]}],
    }
    session._instance.get.side_effect = [first_page, second_page]

    response = CrossApprovalRequestRestConsumer(session).get_cross_approval_requests()

    assert [request.status for request in response.results] == ["approved", "approved"]
    assert session._instance.get.call_count == 2
    first_call = session._instance.get.call_args_list[0]
    assert first_call.args[0] == "https://dojo.example/api/v2/crossapproval_requests/"
    assert first_call.kwargs["headers"] == {
        "Authorization": "Token token",
        "Accept": "application/json",
    }
    assert first_call.kwargs["params"] == {"status": "approved"}