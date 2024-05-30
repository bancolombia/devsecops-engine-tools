import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth import GenericOauth

class TestGenericOauth(unittest.TestCase):

    def setUp(self):
        self.data = {
            "security_auth": {
                "client_id": "dummy_client_id",
                "client_secret": "dummy_client_secret",
                "endpoint": "https://dummy.endpoint",
                "username": "dummy_username",
                "password": "dummy_password",
                "scope": "dummy_scope"
            }
        }
        self.oauth = GenericOauth(self.data)

    def test_process_data(self):
        config = self.oauth.process_data()

        expected_config = {
            "client_id": "dummy_client_id",
            "client_secret": "dummy_client_secret",
            "endpoint": "https://dummy.endpoint",
            "username": "dummy_username",
            "password": "dummy_password",
            "scope": "dummy_scope"
        }
        self.assertEqual(config, expected_config)

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth.GenericOauth.get_access_token_resource_owner')
    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth.GenericOauth.process_data')
    def test_get_access_token_resource_owner(self, mock_process_data, mock_get_access_token_resource_owner):
        mock_process_data.return_value = self.oauth.process_data()
        self.oauth.get_access_token()

        mock_get_access_token_resource_owner.assert_called_once()

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth.requests.request')
    def test_get_access_token_client_credentials_flow(self, mock_request):
        self.oauth.config = self.oauth.process_data()
        self.oauth.config["tenant_id"] = "dummy_tenant_id"
        response_mock = Mock()
        response_mock.status_code = 200
        response_mock.json.return_value = {"access_token": "dummy_access_token"}
        mock_request.return_value = response_mock

        token = self.oauth.get_access_token_client_credentials()

        mock_request.assert_called_once_with(
            "POST",
            "https://dummy.endpoint",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": "dummy_client_id",
                "client_secret": "dummy_client_secret",
                "tenant_id": "dummy_tenant_id",
                "grant_type": "client_credentials",
                "scope": "dummy_scope"
            },
            timeout=5
        )
        self.assertEqual(token, "dummy_access_token")

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth.requests.request')
    def test_get_access_token_resource_owner_flow(self, mock_request):
        self.oauth.config = self.oauth.process_data()
        self.oauth.config["tenant_id"] = "dummy_tenant_id"
        response_mock = Mock()
        response_mock.status_code = 200
        response_mock.json.return_value = {"access_token": "dummy_access_token"}
        mock_request.return_value = response_mock

        token = self.oauth.get_access_token_resource_owner()

        mock_request.assert_called_once_with(
            "POST",
            "https://dummy.endpoint",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": "dummy_client_id",
                "client_secret": "dummy_client_secret",
                "grant_type": "password",
                "scope": "dummy_scope",
                "username": "dummy_username",
                "password": "dummy_password"
            },
            timeout=5
        )
        self.assertEqual(token, "dummy_access_token")