import json
import os
import subprocess
import sys
import tempfile

from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_deserealizator import (
    ScriptDeserealizator,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_RESULT_MODE = "output_lines"


class ScriptTool(ToolGateway):
    """Runs configured script paths and interprets output using RESULT_MODE."""

    TOOL_SCRIPT = "SCRIPT"
    RESULTS_FILE = "results_script.json"

    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        tool_config = config_tool.get(self.TOOL_SCRIPT, {})
        default_severity = tool_config.get("DEFAULT_SEVERITY", "low")
        default_category = tool_config.get("DEFAULT_CATEGORY", "vulnerability")
        timeout_seconds = tool_config.get("TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        rules_config = tool_config.get("RULES", {})
        scripts_root = self._resolve_scripts_root(
            tool_config,
            kwargs.get("secret_tool"),
            kwargs.get("secret_external_checks"),
            kwargs.get("work_folder"),
        )

        results = self._execute_rules(
            rules_config, folders_to_scan, timeout_seconds, scripts_root
        )

        results_path = os.path.abspath(self.RESULTS_FILE)
        with open(results_path, "w") as f:
            json.dump(results, f, indent=4)

        deserealizator = ScriptDeserealizator()
        findings_list = deserealizator.get_list_finding(
            results, default_severity, default_category, rules_config=rules_config
        )

        return findings_list, results_path

    def _resolve_scripts_root(
        self, scripts_config, secret_tool, secret_external_checks, work_folder
    ):
        if not scripts_config.get("USE_EXTERNAL_CHECKS_DIR", False):
            return None

        work_folder = work_folder or tempfile.gettempdir()
        Utils().configurate_external_checks(
            self.TOOL_SCRIPT,
            {self.TOOL_SCRIPT: scripts_config},
            secret_tool,
            secret_external_checks,
            agent_work_folder=work_folder,
        )

        scripts_root = os.path.join(work_folder, "rules", "script")
        scripts_subfolder = scripts_config.get(
            "EXTERNAL_DIR_SCRIPTS_PATH", ""
        ).strip("/\\")
        if scripts_subfolder:
            candidate_path = os.path.join(scripts_root, scripts_subfolder)
            if os.path.isdir(candidate_path):
                return candidate_path

        return scripts_root

    def _execute_rules(
        self, rules_config, folders_to_scan, timeout_seconds, scripts_root=None
    ):
        results = []

        for rule_group in (rules_config or {}).values():
            for rule_id, rule_data in rule_group.items():
                script = self._resolve_script(rule_id, rule_data, scripts_root)
                if script is None:
                    continue

                result_mode = rule_data.get("RESULT_MODE", DEFAULT_RESULT_MODE)

                for folder in folders_to_scan:
                    results.append(
                        self._run_script(
                            rule_id,
                            script,
                            folder,
                            result_mode,
                            timeout_seconds,
                            rule_data.get("severity", "medium"),
                        )
                    )

        return results

    def _resolve_script(self, rule_id, rule_data, scripts_root=None):
        script_path = rule_data.get("SCRIPT_PATH")

        if not script_path:
            logger.warning(f"Rule '{rule_id}' has no SCRIPT_PATH configured, skipping")
            return None

        if not isinstance(script_path, str):
            logger.error(
                f"Rule '{rule_id}' SCRIPT_PATH must be a non-empty string, skipping"
            )
            return None

        if scripts_root:
            if os.path.isabs(script_path):
                logger.error(
                    f"Rule '{rule_id}' SCRIPT_PATH must be relative when using "
                    "external scripts, skipping"
                )
                return None

            scripts_root = os.path.realpath(scripts_root)
            script_path = os.path.realpath(os.path.join(scripts_root, script_path))
            try:
                if os.path.commonpath([scripts_root, script_path]) != scripts_root:
                    raise ValueError("path escapes external scripts directory")
            except ValueError:
                logger.error(
                    f"Rule '{rule_id}' SCRIPT_PATH escapes external scripts "
                    "directory, skipping"
                )
                return None

        extension = os.path.splitext(script_path)[1].lower()
        if extension != ".py":
            logger.error(
                f"Rule '{rule_id}' SCRIPT_PATH must point to a Python file, "
                f"got '{extension or 'no extension'}', skipping"
            )
            return None

        return [sys.executable, script_path]

    def _run_script(
        self, rule_id, script, folder, result_mode, timeout_seconds, severity
    ):
        entry = {
            "rule_id": rule_id,
            "folder": folder,
            "result_mode": result_mode,
            "severity": severity.lower(),
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
        try:
            result = subprocess.run(
                script,
                cwd=folder,
                capture_output=True,
                timeout=timeout_seconds,
                shell=False,
            )
            entry["returncode"] = result.returncode
            entry["stdout"] = result.stdout.decode("utf-8", errors="replace")
            entry["stderr"] = result.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            logger.error(
                f"Rule '{rule_id}' script timed out after {timeout_seconds}s in "
                f"folder '{folder}'"
            )
            entry["stderr"] = "Command timed out"
        except Exception as e:
            logger.error(f"Error executing rule '{rule_id}' script in '{folder}': {e}")
            entry["stderr"] = str(e)

        return entry
