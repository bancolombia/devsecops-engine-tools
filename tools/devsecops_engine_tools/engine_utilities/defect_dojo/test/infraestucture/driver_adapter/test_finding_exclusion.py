import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion import FindingExclusionRestConsumer
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError

class TestFindingExclusionRestConsumer(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion.SessionManager')
    def setUp(self, MockSessionManager):
        self.mock_session = MockSessionManager.return_value
        self.mock_session._token = 'fake_token'
        self.mock_session._host = 'http://fakehost'
        self.mock_session._instance = MagicMock()
        self.consumer = FindingExclusionRestConsumer(self.mock_session)

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion.FindingExclusionList')
    def test_get_finding_exclusions_success(self, MockFindingExclusionList):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'key': 'value'}
        self.mock_session._instance.get.return_value = mock_response
        MockFindingExclusionList.from_dict.return_value = 'finding_exclusion_object'

        request = {'param': 'value'}
        result = self.consumer.get_finding_exclusions(request)

        self.mock_session._instance.get.assert_called_once_with(
            'http://fakehost/api/v2/finding_exclusions/',
            headers={'Authorization': 'Token fake_token', 'Content-Type': 'application/json'},
            params=request,
            verify=False
        )
        MockFindingExclusionList.from_dict.assert_called_once_with({'key': 'value'})
        self.assertEqual(result, 'finding_exclusion_object')

    def test_get_finding_exclusions_api_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'error': 'some error'}
        self.mock_session._instance.get.return_value = mock_response

        request = {'param': 'value'}
        with self.assertRaises(ApiError):
            self.consumer.get_finding_exclusions(request)

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion.logger')
    def test_get_finding_exclusions_exception(self, mock_logger):
        self.mock_session._instance.get.side_effect = Exception('some exception')

        request = {'param': 'value'}
        with self.assertRaises(ApiError):
            self.consumer.get_finding_exclusions(request)

        mock_logger.error.assert_called_once_with('from dict FindingExclusion: some exception')

if __name__ == '__main__':
    unittest.main()