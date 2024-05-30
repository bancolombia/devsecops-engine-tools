import unittest
from unittest.mock import patch, mock_open
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
    update_field)

class TestGenerateFileFromTool(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    @patch('os.path.abspath', return_value='/absolute/path/results.json')
    def test_generate_file_from_tool_nuclei(self, mock_abspath, mock_json_dump, mock_open):
        tool = "nuclei"
        result_list = [
            {
                "results": {
                    "failed_checks": [{"check_id": "ID1", "severity": "high"}]
                },
                "summary": {
                    "passed": 5,
                    "failed": 2,
                    "skipped": 1,
                    "parsing_errors": 0,
                    "resource_count": 10,
                    "checkov_version": "2.0.0"
                }
            },
            {
                "results": {
                    "failed_checks": [{"check_id": "ID2", "severity": "medium"}]
                },
                "summary": {
                    "passed": 3,
                    "failed": 1,
                    "skipped": 0,
                    "parsing_errors": 1,
                    "resource_count": 5,
                    "checkov_version": "2.0.0"
                }
            }
        ]
        rules_doc = {
            "ID1": {"severity": "HIGH"},
            "ID2": {"severity": "MEDIUM"}
        }

        expected_results_data = {
            "check_type": "Api and Web Application",
            "results": {
                "failed_checks": [
                    {"check_id": "ID1", "severity": "high"},
                    {"check_id": "ID2", "severity": "medium"}
                ]
            },
            "summary": {
                "passed": 8,
                "failed": 3,
                "skipped": 1,
                "parsing_errors": 1,
                "resource_count": 15,
                "checkov_version": "2.0.0"
            }
        }

        result = generate_file_from_tool(tool, result_list, rules_doc)

        mock_open.assert_called_once_with('results.json', 'w')
        mock_json_dump.assert_called_once()
        mock_abspath.assert_called_once_with('results.json')
        self.assertEqual(result, '/absolute/path/results.json')

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generate_file_from_tool_key_error(self, mock_json_dump, mock_open):
        tool = "nuclei"
        result_list = [
            {
                "results": {
                    "failed_checks": [{"check_id": "ID1", "severity": "high"}]
                },
                "summary": {
                    "passed": 5,
                    "failed": 2,
                    "skipped": 1,
                    "parsing_errors": 0,
                    "resource_count": 10,
                    "checkov_version": "2.0.0"
                }
            }
        ]
        rules_doc = {}  # Missing keys

        result = generate_file_from_tool(tool, result_list, rules_doc)
        self.assertIsNotNone(result)

    def test_update_field(self):
        elem = {"field1": "value1", "field2": "value2"}
        field = "field2"
        new_value = "new_value"
        expected = {"field1": "value1", "field2": "new_value"}

        result = update_field(elem, field, new_value)
        self.assertEqual(result, expected)