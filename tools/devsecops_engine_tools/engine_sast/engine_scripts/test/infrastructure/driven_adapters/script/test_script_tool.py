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
                    "SCRIPT_PATH": {
                        "Linux": "scripts/check_no_maps.sh",
                        "Darwin": "scripts/check_no_maps.sh",
                        "Windows": "scripts\\check_no_maps.ps1",
                    },
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

    def test_resolve_script_uses_shell_interpreter(self):
        rule_data = CONFIG_TOOL["SCRIPT"]["RULES"]["RULES_ARTIFACT_HYGIENE"]["NO_SOURCE_MAPS"]
        result = self.tool._resolve_script("NO_SOURCE_MAPS", rule_data, "Linux")
        self.assertEqual(result, ["bash", "scripts/check_no_maps.sh"])

    def test_resolve_script_uses_python_interpreter(self):
        rule_data = {"SCRIPT_PATH": {"Linux": "scripts/check.py"}}
        result = self.tool._resolve_script("R1", rule_data, "Linux")
        self.assertEqual(result, [__import__("sys").executable, "scripts/check.py"])

    def test_resolve_script_uses_powershell_interpreter(self):
        rule_data = {"SCRIPT_PATH": {"Windows": "scripts\\check.ps1"}}
        result = self.tool._resolve_script("R1", rule_data, "Windows")
        self.assertEqual(
            result,
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts\\check.ps1"],
        )

    def test_resolve_script_uses_cmd_interpreter(self):
        rule_data = {"SCRIPT_PATH": {"Windows": "scripts\\check.bat"}}
        result = self.tool._resolve_script("R1", rule_data, "Windows")
        self.assertEqual(result, ["cmd", "/c", "scripts\\check.bat"])

    def test_resolve_script_runs_unknown_extension_directly(self):
        rule_data = {"SCRIPT_PATH": {"Linux": "scripts/check"}}
        result = self.tool._resolve_script("R1", rule_data, "Linux")
        self.assertEqual(result, ["scripts/check"])

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_missing_platform_warns_and_skips(self, mock_logger):
        rule_data = {"SCRIPT_PATH": {"Linux": "scripts/check.sh"}}
        result = self.tool._resolve_script("SOME_RULE", rule_data, "SunOS")
        self.assertIsNone(result)
        mock_logger.warning.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_resolve_script_non_string_path_rejected(self, mock_logger):
        rule_data = {"SCRIPT_PATH": {"Linux": ["scripts/check.sh"]}}
        result = self.tool._resolve_script("SOME_RULE", rule_data, "Linux")
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
        entry = self.tool._run_script("R1", ["bash", "check.sh"], "dist", "output_lines", 30, "high")
        self.assertEqual(entry["returncode"], 0)
        self.assertEqual(entry["stdout"], "a.map\n")
        mock_subprocess.assert_called_once_with(
            ["bash", "check.sh"], cwd="dist", capture_output=True, timeout=30, shell=False
        )

    @patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd="find", timeout=30))
    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_run_script_timeout(self, mock_logger, _):
        entry = self.tool._run_script("R1", ["bash", "check.sh"], "dist", "output_lines", 30, "high")
        self.assertIsNone(entry["returncode"])
        self.assertEqual(entry["stderr"], "Command timed out")
        mock_logger.error.assert_called_once()

    @patch("subprocess.run", side_effect=Exception("boom"))
    @patch(
        "devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_tool.logger"
    )
    def test_run_script_generic_exception(self, mock_logger, _):
        entry = self.tool._run_script("R1", ["bash", "check.sh"], "dist", "output_lines", 30, "high")
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
    @patch("platform.system", return_value="Linux")
    def test_run_tool_returns_findings_and_path(
        self, _platform, _abspath, _dump, _open, mock_subprocess
    ):
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=b"app.js.map\n", stderr=b""
        )
        findings, path = self.tool.run_tool(CONFIG_TOOL, ["dist"])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "NO_SOURCE_MAPS")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(path, "/tmp/results_script.json")

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("os.path.abspath", return_value="/tmp/results_script.json")
    @patch("platform.system", return_value="SunOS")
    def test_run_tool_unsupported_platform_no_findings(
        self, _platform, _abspath, _dump, _open
    ):
        findings, path = self.tool.run_tool(CONFIG_TOOL, ["dist"])
        self.assertEqual(findings, [])
        self.assertEqual(path, "/tmp/results_script.json")

    # ------------------------------------------------------------------ #
    # get_scripts_context_from_results                                      #
    # ------------------------------------------------------------------ #

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps(
            [
                {
                    "rule_id": "NO_SOURCE_MAPS",
                    "folder": "dist",
                    "result_mode": "output_lines",
                    "severity": "high",
                    "returncode": 0,
                    "stdout": "app.js.map",
                }
            ]
        ),
    )
    def test_get_scripts_context_from_results(self, _):
        context_list = self.tool.get_scripts_context_from_results("results_script.json")
        self.assertEqual(len(context_list), 1)
        ctx = context_list[0]
        self.assertEqual(ctx.id, "NO_SOURCE_MAPS")
        self.assertEqual(ctx.tool, "Script")
        self.assertEqual(ctx.where, "dist: app.js.map")
        self.assertEqual(ctx.module, "engine_scripts")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps(
            [
                {
                    "rule_id": "NO_SOURCE_MAPS",
                    "folder": "dist",
                    "result_mode": "output_lines",
                    "severity": "high",
                    "returncode": 0,
                    "stdout": "",
                }
            ]
        ),
    )
    def test_get_scripts_context_from_results_no_findings(self, _):
        context_list = self.tool.get_scripts_context_from_results("results_script.json")
        self.assertEqual(context_list, [])


if __name__ == "__main__":
    unittest.main()
