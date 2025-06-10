import unittest
from devsecops_engine_tools.engine_dast.src.domain.model.api_config import ApiConfig

class TestApiConfig(unittest.TestCase):

    def test_api_config_success(self):
        api_data = {
            "endpoint": "https://api.example.com",
            "operations": ["GET /users", "POST /users"]
        }
        config = ApiConfig(api_data)
        self.assertEqual(config.target_type, "API")
        self.assertEqual(config.endpoint, "https://api.example.com")
        self.assertEqual(config.operations, ["GET /users", "POST /users"])
        self.assertIsNone(config.concurrency)
        self.assertIsNone(config.response_size)
        self.assertIsNone(config.bulk_size)
        self.assertIsNone(config.timeout)

    def test_api_config_missing_endpoint(self):
        api_data = {
            "operations": ["GET /users"]
        }
        with self.assertRaises(KeyError):
            ApiConfig(api_data)

    def test_api_config_missing_operations(self):
        api_data = {
            "endpoint": "https://api.example.com"
        }
        with self.assertRaises(KeyError):
            ApiConfig(api_data)