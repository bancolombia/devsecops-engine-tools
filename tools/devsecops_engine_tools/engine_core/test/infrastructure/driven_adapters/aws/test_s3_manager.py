import unittest
from unittest.mock import MagicMock, patch
from unittest import mock
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.s3_manager import S3Manager
import datetime

class S3ManagerTests(unittest.TestCase):
    def setUp(self):
        self.s3_manager = S3Manager()

    @patch("boto3.session.Session.client")
    @patch("devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.aws.s3_manager.assume_role")
    def test_send_metrics(self, mock_assume_role , mock_client):
        # Mock the necessary dependencies
        mock_client.return_value = MagicMock()

        mock_assume_role.return_value.return_value = {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test"
        }

        # Set up test data
        config_tool = {
            "METRICS_MANAGER": {
                "AWS": {
                    "ROLE_ARN": "arn:aws:iam::123456789012:role/MyRole",
                    "REGION_NAME": "us-west-2",
                    "BUCKET": "my-bucket",
                }
            }
        }
        tool = "my-tool"
        file_path = "/path/to/my/file.txt"

        with mock.patch("builtins.open", create=True) as mock_open:
            # Call the method under test
            self.s3_manager.send_metrics(config_tool, tool, file_path)

        # Assert that the necessary methods were called with the correct arguments
        mock_client.assert_called_once_with(
            service_name="s3",
            region_name="us-west-2",
            aws_access_key_id=mock.ANY,
            aws_secret_access_key=mock.ANY,
            aws_session_token=mock.ANY,
        )
        date = datetime.datetime.now()
        mock_client.return_value.put_object.assert_called_once_with(
            Bucket="my-bucket", Key=f"engine_tools/my-tool/{date.strftime('%Y')}/{date.strftime('%m')}/{date.strftime('%d')}/file.txt", Body=mock.ANY
        )