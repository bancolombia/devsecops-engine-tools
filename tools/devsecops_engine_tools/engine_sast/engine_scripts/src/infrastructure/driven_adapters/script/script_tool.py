import json
import hashlib
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
    EXECUTION_RESULTS_FILE = "results_script_execution.json"

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

        execution_results_path = os.path.abspath(self.EXECUTION_RESULTS_FILE)
        with open(execution_results_path, "w") as f:
            json.dump(results, f, indent=4)

        deserealizator = ScriptDeserealizator()
        findings_list = deserealizator.get_list_finding(
            results, default_severity, default_category, rules_config=rules_config
        )

        report = self._build_generic_import_report(
            results, rules_config, default_severity
        )
        results_path = os.path.abspath(self.RESULTS_FILE)
        with open(results_path, "w") as f:
            json.dump(report, f, indent=4)

        return findings_list, results_path

    def _build_generic_import_report(
        self, results, rules_config, default_severity
    ):
        rules_lookup = {
            rule_id: rule_data
            for rule_group in (rules_config or {}).values()
            for rule_id, rule_data in rule_group.items()
        }
        findings = []

        for entry in results:
            rule_id = entry.get("rule_id", "unknown")
            folder = entry.get("folder", "")
            rule_meta = rules_lookup.get(rule_id, {})
            severity = rule_meta.get("severity", default_severity)
            severity = severity.strip().capitalize() if isinstance(severity, str) else "Info"

            for message in ScriptDeserealizator.extract_messages(entry):
                file_path = self._resolve_report_file_path(folder, message)
                finding_identity = "\0".join(
                    (rule_id, file_path or "", message)
                )
                generic_finding = {
                    "title": rule_id,
                    "severity": severity,
                    "description": message,
                    "unique_id_from_tool": hashlib.sha256(
                        finding_identity.encode("utf-8")
                    ).hexdigest(),
                    "static_finding": True,
                    "dynamic_finding": False,
                }
                if file_path:
                    generic_finding["file_path"] = file_path
                guideline = rule_meta.get("guideline")
                if guideline:
                    generic_finding["references"] = guideline
                findings.append(generic_finding)

        return {
            "type": "DevSecOps Engine Scripts",
            "static_tool": True,
            "dynamic_tool": False,
            "findings": findings,
        }

    @staticmethod
    def _resolve_report_file_path(folder, message):
        if not folder or not message:
            return None

        root_path = os.path.realpath(folder)
        candidate_path = message if os.path.isabs(message) else os.path.join(folder, message)
        candidate_path = os.path.realpath(candidate_path)
        try:
            if os.path.commonpath([root_path, candidate_path]) != root_path:
                return None
        except ValueError:
            return None

        if not os.path.isfile(candidate_path):
            return None

        return os.path.relpath(candidate_path, root_path).replace(os.sep, "/")

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

        return os.path.join(work_folder, "rules", "scripts")

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
        script_name = rule_data.get("SCRIPT_NAME")

        if not script_name:
            logger.warning(f"Rule '{rule_id}' has no SCRIPT_NAME configured, skipping")
            return None

        if not isinstance(script_name, str):
            logger.error(
                f"Rule '{rule_id}' SCRIPT_NAME must be a non-empty string, skipping"
            )
            return None

        if (
            script_name in {".", ".."}
            or os.path.basename(script_name) != script_name
            or "/" in script_name
            or "\\" in script_name
        ):
            logger.error(
                f"Rule '{rule_id}' SCRIPT_NAME must contain only a filename, skipping"
            )
            return None

        if os.path.splitext(script_name)[1].lower() != ".py":
            logger.error(
                f"Rule '{rule_id}' SCRIPT_NAME must name a Python file, skipping"
            )
            return None

        if scripts_root:
            scripts_root = os.path.realpath(scripts_root)
            script_path = os.path.realpath(os.path.join(scripts_root, script_name))
            try:
                if os.path.commonpath([scripts_root, script_path]) != scripts_root:
                    raise ValueError("path escapes external scripts directory")
            except ValueError:
                logger.error(
                    f"Rule '{rule_id}' SCRIPT_NAME escapes external scripts "
                    "directory, skipping"
                )
                return None
            return [sys.executable, script_path]

        return [sys.executable, script_name]

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
        script_path = script[-1]
        script_file = (
            script_path if os.path.isabs(script_path) else os.path.join(folder, script_path)
        )
        if not os.path.isfile(script_file):
            entry["stderr"] = f"Configured script not found: {script_path}"
            logger.error(
                f"Rule '{rule_id}' configured script not found: '{script_file}'"
            )
            return entry

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
