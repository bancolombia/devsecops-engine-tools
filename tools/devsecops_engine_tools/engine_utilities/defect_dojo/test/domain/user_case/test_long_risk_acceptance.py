import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.user_case.long_risk_acceptance import (
    LongRiskAcceptanceUserCase,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.long_risk_acceptance import (
    LongRiskAcceptanceRestConsumer,
)


class TestLongRiskAcceptanceUserCase(unittest.TestCase):
    def setUp(self):
        self.mock_rest_long_risk_acceptance = MagicMock(spec=LongRiskAcceptanceRestConsumer)
        self.user_case = LongRiskAcceptanceUserCase(self.mock_rest_long_risk_acceptance)

    def test_execute_success(self):
        long_risk_acceptance_id = 42
        expected_response = {"response": "data"}
        self.mock_rest_long_risk_acceptance.get_long_risk_acceptance.return_value = expected_response

        response = self.user_case.execute(long_risk_acceptance_id)

        self.assertEqual(response, expected_response)
        self.mock_rest_long_risk_acceptance.get_long_risk_acceptance.assert_called_once_with(
            long_risk_acceptance_id
        )


if __name__ == '__main__':
    unittest.main()
