import unittest
from unittest.mock import patch, Mock
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.applications.long_risk_acceptance import (
    LongRiskAcceptance,
)


class TestLongRiskAcceptance(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.long_risk_acceptance.LongRiskAcceptanceRestConsumer')
    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.long_risk_acceptance.LongRiskAcceptanceUserCase')
    def test_get_long_risk_acceptance_success(self, mock_user_case, mock_rest_consumer):
        session = Mock()
        long_risk_acceptance_id = 42
        mock_uc_instance = mock_user_case.return_value
        mock_uc_instance.execute.return_value = 'expected_result'

        result = LongRiskAcceptance.get_long_risk_acceptance(session, long_risk_acceptance_id)

        mock_rest_consumer.assert_called_once_with(session=session)
        mock_user_case.assert_called_once_with(mock_rest_consumer.return_value)
        mock_uc_instance.execute.assert_called_once_with(long_risk_acceptance_id)
        self.assertEqual(result, 'expected_result')

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.long_risk_acceptance.LongRiskAcceptanceRestConsumer')
    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.long_risk_acceptance.LongRiskAcceptanceUserCase')
    def test_get_long_risk_acceptance_api_error(self, mock_user_case, mock_rest_consumer):
        session = Mock()
        long_risk_acceptance_id = 42
        mock_uc_instance = mock_user_case.return_value
        mock_uc_instance.execute.side_effect = ApiError('API error occurred')

        with self.assertRaises(ApiError):
            LongRiskAcceptance.get_long_risk_acceptance(session, long_risk_acceptance_id)

        mock_rest_consumer.assert_called_once_with(session=session)
        mock_user_case.assert_called_once_with(mock_rest_consumer.return_value)
        mock_uc_instance.execute.assert_called_once_with(long_risk_acceptance_id)


if __name__ == '__main__':
    unittest.main()
