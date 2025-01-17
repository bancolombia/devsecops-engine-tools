import unittest
from unittest.mock import patch, Mock
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.applications.finding_exclusion import FindingExclusion

class TestFindingExclusion(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.finding_exclusion.FindingExclusionRestConsumer')
    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.finding_exclusion.FindingExclusionUserCase')
    def test_get_finding_exclusion_success(self, mock_user_case, mock_rest_consumer):
        session = Mock()
        request = {'key': 'value'}
        mock_uc_instance = mock_user_case.return_value
        mock_uc_instance.execute.return_value = 'expected_result'

        result = FindingExclusion.get_finding_exclusion(session, **request)

        mock_rest_consumer.assert_called_once_with(session=session)
        mock_user_case.assert_called_once_with(mock_rest_consumer.return_value)
        mock_uc_instance.execute.assert_called_once_with(request)
        self.assertEqual(result, 'expected_result')

    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.finding_exclusion.FindingExclusionRestConsumer')
    @patch('devsecops_engine_tools.engine_utilities.defect_dojo.applications.finding_exclusion.FindingExclusionUserCase')
    def test_get_finding_exclusion_api_error(self, mock_user_case, mock_rest_consumer):
        session = Mock()
        request = {'key': 'value'}
        mock_uc_instance = mock_user_case.return_value
        mock_uc_instance.execute.side_effect = ApiError('API error occurred')

        with self.assertRaises(ApiError):
            FindingExclusion.get_finding_exclusion(session, **request)

        mock_rest_consumer.assert_called_once_with(session=session)
        mock_user_case.assert_called_once_with(mock_rest_consumer.return_value)
        mock_uc_instance.execute.assert_called_once_with(request)