import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool import JwtTool

class TestJwtTool(unittest.TestCase):

    def setUp(self):
        self.target_config_mock = Mock()
        self.jwt_tool = JwtTool(target_config=self.target_config_mock)

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_verify_jwt_alg(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.return_value = {"alg": "none"}
        
        result = self.jwt_tool.verify_jwt_alg(token)

        mock_get_unverified_header.assert_called_once_with(token)
        self.assertEqual(result["check-id"], "ENGINE_JWT_001")
        self.assertTrue("description" in result)

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_verify_jws_alg(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.return_value = {"alg": "ES256"}

        result = self.jwt_tool.verify_jws_alg(token)

        mock_get_unverified_header.assert_called_once_with(token)
        self.assertEqual(result["check-id"], "ENGINE_JWT_002")
        self.assertTrue("description" in result)

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_verify_jwe(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.side_effect = [
            {"enc": "A256GCM"},
            {"alg": "RSA-OAEP"}
        ]

        result = self.jwt_tool.verify_jwe(token)

        self.assertEqual(mock_get_unverified_header.call_count, 2)
        self.assertEqual(result["check-id"], "ENGINE_JWT_003")
        self.assertIn("Algoritmo", result["description"])

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_check_token_jwe(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.return_value = {"enc": "A256GCM"}

        with patch.object(self.jwt_tool, 'verify_jwe', return_value={"check-id": "ENGINE_JWT_003"}) as mock_verify_jwe:
            result = self.jwt_tool.check_token(token)
            mock_verify_jwe.assert_called_once_with(token)
            self.assertEqual(result["check-id"], "ENGINE_JWT_003")

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_check_token_jwt(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.return_value = {"typ": "JWT"}

        with patch.object(self.jwt_tool, 'verify_jwt_alg', return_value={"check-id": "ENGINE_JWT_001"}) as mock_verify_jwt_alg:
            result = self.jwt_tool.check_token(token)
            mock_verify_jwt_alg.assert_called_once_with(token)
            self.assertEqual(result["check-id"], "ENGINE_JWT_001")

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.jwt.get_unverified_header')
    def test_check_token_jws(self, mock_get_unverified_header):
        token = "dummy_token"
        mock_get_unverified_header.return_value = {}

        with patch.object(self.jwt_tool, 'verify_jws_alg', return_value={"check-id": "ENGINE_JWT_002"}) as mock_verify_jws_alg:
            result = self.jwt_tool.check_token(token)
            mock_verify_jws_alg.assert_called_once_with(token)
            self.assertEqual(result["check-id"], "ENGINE_JWT_002")

    def test_configure_tool(self):
        operation_mock = Mock()
        operation_mock.authentication_gateway = {"type": "JWT"}
        target_data_mock = Mock()
        target_data_mock.operations = [operation_mock]

        result = self.jwt_tool.configure_tool(target_data_mock)

        self.assertIn(operation_mock, result)

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.jwt.jwt_tool.generate_file_from_tool')
    def test_run_tool(self, mock_generate_file_from_tool):
        target_data_mock = Mock()
        config_tool_mock = Mock()
        jwt_operation_mock = Mock()
        jwt_operation_mock.authenticate.return_value = "dummy_token"
        self.jwt_tool.configure_tool = Mock(return_value=[jwt_operation_mock])
        self.jwt_tool.execute = Mock(return_value=[{"check-id": "ENGINE_JWT_001"}])
        self.jwt_tool.deserialize_results = Mock(return_value=["finding"])

        findings, path_file_results = self.jwt_tool.run_tool(target_data_mock, config_tool_mock)

        self.jwt_tool.configure_tool.assert_called_once_with(target_data_mock)
        self.jwt_tool.execute.assert_called_once_with([jwt_operation_mock])
        self.jwt_tool.deserialize_results.assert_called_once_with([{"check-id": "ENGINE_JWT_001"}])
        mock_generate_file_from_tool.assert_called_once_with(
            self.jwt_tool.TOOL, [{"check-id": "ENGINE_JWT_001"}], config_tool_mock
        )
        self.assertEqual(findings, ["finding"])