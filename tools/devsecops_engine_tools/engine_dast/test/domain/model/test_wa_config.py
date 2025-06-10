import unittest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_dast.src.domain.model.wa_config import WaConfig

class TestWaConfig(unittest.TestCase):

    def test_wa_config_init(self):
        data = {
            "endpoint": "https://web.example.com",
            "data": {"headers": {}, "payload": {}}
        }
        mock_auth_gateway = MagicMock()
        config = WaConfig(data, mock_auth_gateway)
        self.assertEqual(config.target_type, "WA")
        self.assertEqual(config.url, "https://web.example.com")
        self.assertEqual(config.data, {"headers": {}, "payload": {}})
        self.assertIsNone(config.concurrency)
        self.assertIsNone(config.response_size)
        self.assertIsNone(config.bulk_size)
        self.assertIsNone(config.timeout)

    def test_authenticate_adds_credentials(self):
        data = {
            "endpoint": "https://web.example.com",
            "data": {"headers": {}, "payload": {}}
        }
        mock_auth_gateway = MagicMock()
        mock_auth_gateway.get_credentials.return_value = ("Authorization", "Bearer token123")
        config = WaConfig(data, mock_auth_gateway)
        config.authentication_gateway = mock_auth_gateway  # Ensure attribute exists
        config.authenticate()
        self.assertIn("Authorization", config.data["headers"])
        self.assertEqual(config.data["headers"]["Authorization"], "Bearer token123")

    def test_authenticate_no_credentials(self):
        data = {
            "endpoint": "https://web.example.com",
            "data": {"headers": {}, "payload": {}}
        }
        mock_auth_gateway = MagicMock()
        mock_auth_gateway.get_credentials.return_value = None
        config = WaConfig(data, mock_auth_gateway)
        config.authentication_gateway = mock_auth_gateway
        config.authenticate()
        self.assertEqual(config.data["headers"], {})
