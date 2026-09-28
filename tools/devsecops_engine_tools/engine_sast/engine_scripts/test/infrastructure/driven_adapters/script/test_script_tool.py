import json
import os
import unittest
from unittest.mock import MagicMock, mock_open, patch

from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool import (
    ScriptTool,
)


CONFIG_TOOL = {
    "SCRIPT": {
        "TIMEOUT_SECONDS": 30,
        "DEFAULT_SEVERITY": "high",
        "DEFAULT_CATEGORY": "vulnerability",
        "RULES": {
            "RULES_ARTIFACT_HYGIENE": {
                "NO_SOURCE_MAPS": {
                    "SCRIPT_PATH": "scripts/check_no_maps.py",
                    "RESULT_MODE": "output_lines",
                    "severity": "High",
                    "category": "Vulnerability",
                }
            }
        },
    }
}


class TestScriptTool(unittest.TestCase):
    def setUp(self):
        self.tool = ScriptTool()

    # ------------------------------------------------------------------ #
    # _resolve_script                                                      #
    # ------------------------------------------------------------------ #

    def test_resolve_script_uses_python_interpreter(self):
        rule_data = CONFIG_TOOL["SCRIPT"]["RULES"]["RULES_ARTIFACT_HYGIENE"]["NO_SOURCE_MAPS"]
        result = self.tool._resolve_script("NO_SOURCE_MAPS", rule_data)
        self.assertEqual(
            result, [__import__("sys").executable, "scripts/check_no_maps.py"]
        )

    def test_resolve_script_rejects_non_python_extensions(self):
        for script_path in (
            "scripts/check.sh",
            "scripts/check.ps1",
            "scripts/check.bat",
            "scripts/check.cmd",
            "scripts/check",
        ):
            with self.subTest(script_path=script_path):
                rule_data = {"SCRIPT_PATH": script_path}
                self.assertIsNone(self.tool._resolve_script("R1", rule_data))

    def test_resolve_script_uses_downloaded_scripts_root(self):
        rule_data = {"SCRIPT_PATH": "scripts/check.py"}
        result = self.tool._resolve_script(
            "R1", rule_data, "/tmp/rules/script"
        )
        self.assertEqual(
            result,
            [__import__("sys").executable, "/tmp/rules/script/scripts/check.py"],
        )

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.Utils"
    )
    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.os.path.isdir",
        return_value=True,
    )
    def test_resolve_scripts_root_downloads_external_scripts(
        self, _isdir, mock_utils_cls
    ):
        scripts_config = {
            "USE_EXTERNAL_CHECKS_DIR": True,
            "EXTERNAL_DIR_OWNER": "org",
            "EXTERNAL_DIR_REPOSITORY": "script-assets",
            "EXTERNAL_DIR_SCRIPTS_PATH": "artifact_checks",
            "APP_ID_GITHUB": "123",
            "INSTALLATION_ID_GITHUB": "456",
        }

        result = self.tool._resolve_scripts_root(
            scripts_config, None, "github_token:token", "/tmp/agent"
        )

        mock_utils_cls.return_value.configurate_external_checks.assert_called_once_with(
            "SCRIPT",
            {"SCRIPT": scripts_config},
            None,
            "github_token:token",
            agent_work_folder="/tmp/agent",
        )
        self.assertEqual(result, "/tmp/agent/rules/script/artifact_checks")

    def test_resolve_scripts_root_disabled_uses_scanned_repository(self):
        result = self.tool._resolve_scripts_root(
            {"USE_EXTERNAL_CHECKS_DIR": False}, None, None, "/tmp/agent"
        )
        self.assertIsNone(result)

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_rejects_path_outside_external_root(self, mock_logger):
        rule_data = {"SCRIPT_PATH": "../../outside.py"}
        result = self.tool._resolve_script(
            "R1", rule_data, "/tmp/rules/script"
        )
        self.assertIsNone(result)
        mock_logger.error.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_rejects_absolute_external_path(self, mock_logger):
        rule_data = {"SCRIPT_PATH": "/tmp/other/check.py"}
        result = self.tool._resolve_script(
            "R1", rule_data, "/tmp/rules/script"
        )
        self.assertIsNone(result)
        mock_logger.error.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_missing_path_warns_and_skips(self, mock_logger):
        rule_data = {}
        result = self.tool._resolve_script("SOME_RULE", rule_data)
        self.assertIsNone(result)
        mock_logger.warning.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_non_string_path_rejected(self, mock_logger):
        rule_data = {"SCRIPT_PATH": ["scripts/check.py"]}
        result = self.tool._resolve_script("SOME_RULE", rule_data)
        self.assertIsNone(result)
        mock_logger.error.assert_called_once()

    # ------------------------------------------------------------------ #
    # _run_script                                                          #
    # ------------------------------------------------------------------ #

    @patch("subprocess.run")
    def test_run_script_success(self, mock_subprocess):
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=b"a.map\n", stderr=b""
        )
        script = [__import__("sys").executable, "check.py"]
        entry = self.tool._run_script("R1", script, "dist", "output_lines", 30, "high")
        self.assertEqual(entry["returncode"], 0)
        self.assertEqual(entry["stdout"], "a.map\n")
        mock_subprocess.assert_called_once_with(
            script, cwd="dist", capture_output=True, timeout=30, shell=False
        )

    @patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd="find", timeout=30))
    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_run_script_timeout(self, mock_logger, _):
        entry = self.tool._run_script("R1", [__import__("sys").executable, "check.py"], "dist", "output_lines", 30, "high")
        self.assertIsNone(entry["returncode"])
        self.assertEqual(entry["stderr"], "Command timed out")
        mock_logger.error.assert_called_once()

    @patch("subprocess.run", side_effect=Exception("boom"))
    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_run_script_generic_exception(self, mock_logger, _):
        entry = self.tool._run_script("R1", [__import__("sys").executable, "check.py"], "dist", "output_lines", 30, "high")
        self.assertIsNone(entry["returncode"])
        self.assertEqual(entry["stderr"], "boom")
        mock_logger.error.assert_called_once()

    # ------------------------------------------------------------------ #
    # run_tool                                                             #
    # ------------------------------------------------------------------ #

    @patch("subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("os.path.abspath", return_value="/tmp/results_script.json")
    def test_run_tool_returns_findings_and_path(
        self, _abspath, _dump, _open, mock_subprocess
    ):
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=b"app.js.map\n", stderr=b""
        )
        findings, path = self.tool.run_tool(CONFIG_TOOL, ["dist"])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "NO_SOURCE_MAPS")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(path, "/tmp/results_script.json")

if __name__ == "__main__":
    unittest.main()
