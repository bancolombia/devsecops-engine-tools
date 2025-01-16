import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.finding_exclusion import FindingExclusionUserCase
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding_exclusion import FindingExclusionRestConsumer

class TestFindingExclusionUserCase(unittest.TestCase):
    def setUp(self):
        self.mock_rest_finding_exclusion = MagicMock(spec=FindingExclusionRestConsumer)
        self.user_case = FindingExclusionUserCase(self.mock_rest_finding_exclusion)

    def test_execute_success(self):
        request = {"some": "data"}
        expected_response = {"response": "data"}
        self.mock_rest_finding_exclusion.get_finding_exclusions.return_value = expected_response

        response = self.user_case.execute(request)

        self.assertEqual(response, expected_response)
        self.mock_rest_finding_exclusion.get_finding_exclusions.assert_called_once_with(request)

    def test_execute_no_data(self):
        request = {}
        expected_response = {"response": "no_data"}
        self.mock_rest_finding_exclusion.get_finding_exclusions.return_value = expected_response

        response = self.user_case.execute(request)

        self.assertEqual(response, expected_response)
        self.mock_rest_finding_exclusion.get_finding_exclusions.assert_called_once_with(request)

if __name__ == '__main__':
    unittest.main()