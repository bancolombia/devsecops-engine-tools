import unittest
from datetime import datetime
from devsecops_engine_tools.engine_core.src.domain.model.finding import Category
from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_deserealizator import (
    ScriptDeserealizator,
)


class TestScriptDeserealizator(unittest.TestCase):
    def setUp(self):
        self.deserealizator = ScriptDeserealizator()

    # ------------------------------------------------------------------ #
    # extract_messages                                                    #
    # ------------------------------------------------------------------ #

    def test_extract_messages_execution_error(self):
        entry = {"rule_id": "R1", "returncode": None, "stderr": "binary not found"}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(len(result), 1)
        self.assertIn("could not be executed", result[0])
        self.assertIn("binary not found", result[0])

    def test_extract_messages_output_lines_default(self):
        entry = {"rule_id": "R1", "returncode": 0, "stdout": "a.map\nb.map\n"}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, ["a.map", "b.map"])

    def test_extract_messages_output_lines_empty(self):
        entry = {"rule_id": "R1", "returncode": 0, "stdout": "  \n  "}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, [])

    def test_extract_messages_exit_code_failure(self):
        entry = {"rule_id": "R1", "returncode": 1, "result_mode": "exit_code", "stdout": ""}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(len(result), 1)
        self.assertIn("exit code 1", result[0])

    def test_extract_messages_exit_code_success(self):
        entry = {"rule_id": "R1", "returncode": 0, "result_mode": "exit_code", "stdout": ""}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, [])

    def test_extract_messages_json_stdout_valid(self):
        entry = {
            "rule_id": "R1",
            "returncode": 0,
            "result_mode": "json_stdout",
            "stdout": '[{"message": "found map file"}, {"message": "another one"}]',
        }
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, ["found map file", "another one"])

    def test_extract_messages_json_stdout_invalid(self):
        entry = {
            "rule_id": "R1",
            "returncode": 0,
            "result_mode": "json_stdout",
            "stdout": "not json",
        }
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(len(result), 1)
        self.assertIn("Invalid JSON output", result[0])

    def test_extract_messages_json_stdout_empty(self):
        entry = {"rule_id": "R1", "returncode": 0, "result_mode": "json_stdout", "stdout": ""}
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, [])

    def test_extract_messages_json_stdout_not_a_list(self):
        entry = {
            "rule_id": "R1",
            "returncode": 0,
            "result_mode": "json_stdout",
            "stdout": '{"message": "not a list"}',
        }
        result = ScriptDeserealizator.extract_messages(entry)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------ #
    # get_list_finding                                                     #
    # ------------------------------------------------------------------ #

    def test_get_list_finding_empty(self):
        result = self.deserealizator.get_list_finding([], "high")
        self.assertEqual(result, [])

    def test_get_list_finding_uses_default_severity(self):
        results = [
            {
                "rule_id": "NO_SOURCE_MAPS",
                "folder": "dist",
                "result_mode": "output_lines",
                "returncode": 0,
                "stdout": "app.js.map",
            }
        ]
        findings = self.deserealizator.get_list_finding(results, "high")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.id, "NO_SOURCE_MAPS")
        self.assertEqual(finding.where, "dist: app.js.map")
        self.assertEqual(finding.description, "app.js.map")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.category, Category.VULNERABILITY)
        self.assertEqual(finding.tool, "Script")
        self.assertEqual(finding.module, "engine_scripts")
        self.assertEqual(finding.identification_date, datetime.now().strftime("%d%m%Y"))

    def test_get_list_finding_uses_rules_config_override(self):
        results = [
            {
                "rule_id": "NO_SOURCE_MAPS",
                "folder": "dist",
                "result_mode": "output_lines",
                "returncode": 0,
                "stdout": "app.js.map",
            }
        ]
        rules_config = {
            "RULES_ARTIFACT_HYGIENE": {
                "NO_SOURCE_MAPS": {
                    "severity": "Critical",
                    "description": "Configured description",
                    "guideline": "https://example.org/no-source-maps",
                }
            }
        }
        findings = self.deserealizator.get_list_finding(
            results, "low", rules_config=rules_config
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].description, "Configured description")
        self.assertEqual(findings[0].category, Category.VULNERABILITY)
        self.assertEqual(findings[0].requirements, "https://example.org/no-source-maps")

    def test_get_list_finding_no_messages_no_findings(self):
        results = [
            {
                "rule_id": "NO_SOURCE_MAPS",
                "folder": "dist",
                "result_mode": "output_lines",
                "returncode": 0,
                "stdout": "",
            }
        ]
        findings = self.deserealizator.get_list_finding(results, "high")
        self.assertEqual(findings, [])

    def test_get_list_finding_execution_error_still_reported(self):
        results = [
            {
                "rule_id": "NO_SOURCE_MAPS",
                "folder": "dist",
                "result_mode": "output_lines",
                "returncode": None,
                "stderr": "command not found",
            }
        ]
        findings = self.deserealizator.get_list_finding(results, "high")
        self.assertEqual(len(findings), 1)
        self.assertIn("could not be executed", findings[0].description)

    def test_get_list_finding_multiple_lines_multiple_findings(self):
        results = [
            {
                "rule_id": "NO_SOURCE_MAPS",
                "folder": "dist",
                "result_mode": "output_lines",
                "returncode": 0,
                "stdout": "a.map\nb.map",
            }
        ]
        findings = self.deserealizator.get_list_finding(results, "high")
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
