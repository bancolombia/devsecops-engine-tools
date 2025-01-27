import unittest
import os
import json
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool import generate_file_from_tool  # Asegúrate de ajustar el import al módulo correcto

class TestGenerateFileFromTool(unittest.TestCase):

    def setUp(self):
        self.tool_name = "JWT"
        self.result_scans = [
            {
                "check_id": "JWT_ALGORITHM",
                "cvss": 7.5,
                "matched-at": "src/auth/token.py",
                "description": "The algorithm 'none' is insecure.",
                "severity": "high",
                "remediation": "Use a secure algorithm like RS256 or HS256."
            }
        ]
        self.config_tool = {
            "RULES": {
                "JWT_ALGORITHM": {
                    "description": "Evaluate JSON Web token's algorithm",
                    "severity": "high",
                    "cvss": 7.5,
                    "helpUri": "https://example.com/jwt_algorithm"
                }
            }
        }

    def test_generate_file_creation(self):
        sarif_file = generate_file_from_tool(self.tool_name, self.result_scans, self.config_tool)

        self.assertTrue(os.path.exists(sarif_file))

        with open(sarif_file, 'r', encoding='utf-8') as file:
            sarif_content = json.load(file)

        self.assertEqual(sarif_content["version"], "2.1.0")
        self.assertEqual(sarif_content["runs"][0]["tool"]["driver"]["name"], self.tool_name)

        rules = sarif_content["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "JWT_ALGORITHM")
        self.assertEqual(rules[0]["shortDescription"]["text"], "Evaluate JSON Web token's algorithm")
        self.assertEqual(rules[0]["properties"]["severity"], "high")
        self.assertEqual(rules[0]["properties"]["cvss"], 7.5)

        results = sarif_content["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "JWT_ALGORITHM")
        self.assertEqual(results[0]["message"]["text"], "The algorithm 'none' is insecure.")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/auth/token.py")
        self.assertEqual(results[0]["properties"]["severity"], "high")
        self.assertEqual(results[0]["properties"]["cvss"], 7.5)
        self.assertEqual(results[0]["properties"]["remediation"], "Use a secure algorithm like RS256 or HS256.")

        os.remove(sarif_file)

    def test_generate_file_empty_results(self):
        empty_results = []
        sarif_file = generate_file_from_tool(self.tool_name, empty_results, self.config_tool)

        self.assertTrue(os.path.exists(sarif_file))

        with open(sarif_file, 'r', encoding='utf-8') as file:
            sarif_content = json.load(file)

        results = sarif_content["runs"][0]["results"]
        self.assertEqual(len(results), 0)

        os.remove(sarif_file)

    def test_generate_file_empty_rules(self):
        empty_config_tool = {"RULES": {}}
        sarif_file = generate_file_from_tool(self.tool_name, self.result_scans, empty_config_tool)

        self.assertTrue(os.path.exists(sarif_file))

        with open(sarif_file, 'r', encoding='utf-8') as file:
            sarif_content = json.load(file)

        rules = sarif_content["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 0)

        os.remove(sarif_file)
