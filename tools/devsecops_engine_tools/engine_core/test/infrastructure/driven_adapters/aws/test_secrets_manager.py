import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager import (
    SecretsManager,
)


class SecretsManagerTests(unittest.TestCase):
    def setUp(self):
        self.secrets_manager = SecretsManager()

    @patch("boto3.session.Session.client")
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager.validate_execution_account"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.secrets_manager.assume_role"
    )
    def test_get_secret_with_execution_different_account(
        self, mock_assume_role, mock_validate_execution_account, mock_client
    ):
        mock_client.return_value = MagicMock()

        config_tool = {
            "SECRET_MANAGER": {
                "AWS": {
                    "EXECUTION_DIFFERENT_ACCOUNT": True,
                    "ROLE_ARN_DIFFERENT_ACCOUNT": "arn:aws:iam::123456789012:role/MyRole",
                    "REGION_NAME": "us-west-2",
                    "SECRET_NAME_DIFFERENT_ACCOUNT": "my-secret-different-account",
                }
            }
        }
        mock_validate_execution_account.return_value = True
        mock_assume_role.return_value = {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token",
        }

        mock_client.return_value.get_secret_value.return_value = {
            "SecretString": '{"username": "admin", "password": "password123"}'
        }

        secret = self.secrets_manager.get_secret(config_tool)

        assert secret == {"username": "admin", "password": "password123"}
        mock_client.assert_called_once_with(
            service_name="secretsmanager",
            region_name="us-west-2",
            aws_access_key_id="access_key_id",
            aws_secret_access_key="secret_access_key",
            aws_session_token="session_token",
        )
        mock_client.return_value.get_secret_value.assert_called_once_with(
            SecretId="my-secret-different-account"
        )
