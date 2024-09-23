from unittest.mock import MagicMock, patch

from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.engagement import (
    EngagementUserCase,
)

def test_execute():
    mock_engagement_rest_consumer = MagicMock()

    EngagementUserCase(mock_engagement_rest_consumer).execute(MagicMock())

    mock_engagement_rest_consumer.get_engagements_by_request.assert_called_once()