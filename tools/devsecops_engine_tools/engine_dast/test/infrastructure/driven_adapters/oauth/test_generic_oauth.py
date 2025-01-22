import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.oauth.generic_oauth import GenericOauth

class TestGenericOauth(unittest.TestCase):

    def setUp(self):
        self.data = {
        "security_auth": {
          "type": "oauth",
          "method": "POST",
          "path": "oauth2/token",
          "grant_type": "client_credentials",
          "scope": "TermExample:read:user",
          "client_id": "dummy-id",
          "client_secret": "dummy-secret",
          "headers": {
              "content-type": "application/x-www-form-urlencoded",
              "accept": "application/json"
          }
        }
        }
        self.oauth = GenericOauth(self.data, "example.com")

    def test_process_data(self):
        config = self.oauth.process_data()

        expected_config = {
            "method": "POST",
            "path": "oauth2/token",
            "grant_type": "client_credentials",
            "scope": "TermExample:read:user",
            "headers": {
              "content-type": "application/x-www-form-urlencoded",
              "accept": "application/json"
          },
            "client_secret": "dummy-secret",
            "client_id": "dummy-id"
        }
        self.assertEqual(config, expected_config)

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
            'POST', 'example.comoauth2/token', headers={'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json'}, data={'client_id': 'dummy-id', 'client_secret': 'dummy-secret', 'grant_type': 'client_credentials', 'scope': 'TermExample:read:user'}, timeout=5
        )
        self.assertEqual(token, ('Authorization', 'Bearer dummy_access_token'))