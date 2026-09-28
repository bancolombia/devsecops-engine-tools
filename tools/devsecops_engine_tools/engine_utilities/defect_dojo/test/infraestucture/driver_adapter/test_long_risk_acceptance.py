import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance import (
    LongRiskAcceptanceRestConsumer,
)
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


class TestLongRiskAcceptanceRestConsumer(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance.SessionManager')
    def setUp(self, MockSessionManager):
        self.mock_session = MockSessionManager.return_value
        self.mock_session._token = 'fake_token'
        self.mock_session._host = 'http://fakehost'
        self.mock_session._instance = MagicMock()
        self.consumer = LongRiskAcceptanceRestConsumer(self.mock_session)

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance.LongRiskAcceptance')
    def test_get_long_risk_acceptance_success(self, MockLongRiskAcceptance):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'id': 42, 'expiration_date': '2026-12-15T00:00:00-05:00'}
        self.mock_session._instance.get.return_value = mock_response
        MockLongRiskAcceptance.from_dict.return_value = 'long_risk_acceptance_object'

        result = self.consumer.get_long_risk_acceptance(42)

        self.mock_session._instance.get.assert_called_once_with(
            'http://fakehost/api/v2/long_risk_acceptance/42/',
            headers={'Authorization': 'Token fake_token', 'Content-Type': 'application/json'},
            verify=False
        )
        MockLongRiskAcceptance.from_dict.assert_called_once_with(
            {'id': 42, 'expiration_date': '2026-12-15T00:00:00-05:00'}
        )
        self.assertEqual(result, 'long_risk_acceptance_object')

    def test_get_long_risk_acceptance_api_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'error': 'some error'}
        self.mock_session._instance.get.return_value = mock_response

        with self.assertRaises(ApiError):
            self.consumer.get_long_risk_acceptance(42)

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance.logger')
    def test_get_long_risk_acceptance_exception(self, mock_logger):
        self.mock_session._instance.get.side_effect = Exception('some exception')

        with self.assertRaises(ApiError):
            self.consumer.get_long_risk_acceptance(42)

        mock_logger.error.assert_called_once_with('from dict LongRiskAcceptance: some exception')


if __name__ == '__main__':
    unittest.main()
