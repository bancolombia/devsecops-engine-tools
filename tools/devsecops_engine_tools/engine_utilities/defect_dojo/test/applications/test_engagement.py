from unittest.mock import MagicMock, patch

from devsecops_engine_tools.engine_utilities.defect_dojo.applications.engagement import (
    Engagement,
)


@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.engagement.SessionManager"
)
@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.engagement.EngagementRestConsumer"
)
def test_get_engagements(mock_engagement_rest_consumer, mock_session_manager):
    mock_session_manager.return_value = MagicMock()
    mock_engagement_rest_consumer.return_value.get_engagements_by_request.return_value = (
        "response"
    )
    request_is = MagicMock()
    request = MagicMock()
    assert Engagement.get_engagements(request_is, request) == "response"
    mock_session_manager.assert_called_once()
    mock_engagement_rest_consumer.assert_called_once_with(
        request_is, session=mock_session_manager.return_value
    )
    mock_engagement_rest_consumer.return_value.get_engagements_by_request.assert_called_once_with(
        request
    )


@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.engagement.SessionManager"
)
@patch(
    "devsecops_engine_tools.engine_utilities.defect_dojo.applications.engagement.EngagementRestConsumer"
)
def test_get_engagements_raises_api_error(
    mock_engagement_rest_consumer, mock_session_manager
):
    mock_session_manager.return_value = MagicMock()
    mock_engagement_rest_consumer.return_value.get_engagements_by_request.side_effect = Exception(
        "error"
    )
    request_is = MagicMock()
    request = MagicMock()
    try:
        Engagement.get_engagements(request_is, request)
        assert False
    except Exception as e:
        assert str(e) == "error"
    mock_session_manager.assert_called_once()
    mock_engagement_rest_consumer.assert_called_once_with(
        request_is, session=mock_session_manager.return_value
    )
    mock_engagement_rest_consumer.return_value.get_engagements_by_request.assert_called_once_with(
        request
    )
