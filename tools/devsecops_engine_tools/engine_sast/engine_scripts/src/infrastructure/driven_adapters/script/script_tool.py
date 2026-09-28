import json
import os
import platform
import subprocess
import sys
from typing import List

from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.model.context_script import (
    ContextScript,
)
from devsecops_engine_tools.engine_sast.engine_scripts.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_scripts.src.infrastructure.driven_adapters.script.script_deserealizator import (
    ScriptDeserealizator,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_RESULT_MODE = "output_lines"
SCRIPT_INTERPRETERS = {
    ".py": lambda: [sys.executable],
    ".sh": lambda: ["bash"],
    ".ps1": lambda: ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"],
    ".bat": lambda: ["cmd", "/c"],
    ".cmd": lambda: ["cmd", "/c"],
}


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

        results = self._execute_rules(rules_config, folders_to_scan, timeout_seconds)

        results_path = os.path.abspath(self.RESULTS_FILE)
        with open(results_path, "w") as f:
            json.dump(results, f, indent=4)

        deserealizator = ScriptDeserealizator()
        findings_list = deserealizator.get_list_finding(
            results, default_severity, default_category, rules_config=rules_config
        )

        return findings_list, results_path

    def get_scripts_context_from_results(self, path_file_results: str) -> List[ContextScript]:
        with open(path_file_results, "r") as f:
            results = json.load(f)

        context_list = []
        for entry in results:
            folder = entry.get("folder", "unknown")
            for message in ScriptDeserealizator.extract_messages(entry):
                context_script = ContextScript(
                    id=entry.get("rule_id", "unknown"),
                    check_name=message,
                    check_class="script",
                    severity=entry.get("severity", "medium"),
                    where=f"{folder}: {message}",
                    resource=folder,
                    description=message,
                    module="engine_scripts",
                    tool="Script",
                )
                context_list.append(context_script)

        return context_list

    def _execute_rules(self, rules_config, folders_to_scan, timeout_seconds):
        results = []
        os_platform = platform.system()

        for rule_group in (rules_config or {}).values():
            for rule_id, rule_data in rule_group.items():
                script = self._resolve_script(rule_id, rule_data, os_platform)
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

    def _resolve_script(self, rule_id, rule_data, os_platform):
        script_paths = rule_data.get("SCRIPT_PATH", {})
        if not isinstance(script_paths, dict):
            logger.error(f"Rule '{rule_id}' SCRIPT_PATH must map platform names to paths")
            return None

        script_path = script_paths.get(os_platform)

        if not script_path:
            logger.warning(
                f"Rule '{rule_id}' has no script path configured for platform "
                f"'{os_platform}', skipping"
            )
            return None

        if not isinstance(script_path, str):
            logger.error(
                f"Rule '{rule_id}' SCRIPT_PATH for '{os_platform}' must be a "
                "non-empty string, skipping"
            )
            return None

        extension = os.path.splitext(script_path)[1].lower()
        interpreter_factory = SCRIPT_INTERPRETERS.get(extension)
        interpreter = interpreter_factory() if interpreter_factory else []
        return interpreter + [script_path]

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
