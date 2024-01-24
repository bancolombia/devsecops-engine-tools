import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.aws import (
    assume_role, validate_execution_account
)
import os

class TestAssumeRole(unittest.TestCase):
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.helpers.aws.boto3.client"
    )
    def test_assume_role(self, mock_sts_client):
        role_arn = "arn:aws:iam::123456789012:role/MyRole"
        mock_sts_client.return_value = MagicMock()
        mock_sts_client.return_value.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ACCESS_KEY",
                "SecretAccessKey": "SECRET_KEY",
                "SessionToken": "SESSION_TOKEN",
                "Expiration": "2022-01-01T00:00:00Z",
            }
        }

        result = assume_role(role_arn)

        mock_sts_client.assert_called_with("sts")
        mock_sts_client.return_value.assume_role.assert_called_with(
            RoleArn=role_arn, RoleSessionName="DevSecOpsTools"
        )

        expected_result = {
            "AccessKeyId": "ACCESS_KEY",
            "SecretAccessKey": "SECRET_KEY",
            "SessionToken": "SESSION_TOKEN",
            "Expiration": "2022-01-01T00:00:00Z",
        }
        self.assertEqual(result, expected_result)

    def test_validate_execution_account(self):
        different_account = ["account1", "account2", "account3"]
        os.environ["AZP_POOL"] = "account2"

        result = validate_execution_account(different_account)

        self.assertTrue(result)

        os.environ["AZP_POOL"] = "account4"

        result = validate_execution_account(different_account)

        self.assertFalse(result)