import json
from dataclasses import dataclass
from datetime import datetime

from devsecops_engine_tools.engine_core.src.domain.model.finding import Category, Finding


@dataclass
class ScriptDeserealizator:
    @staticmethod
    def extract_messages(entry: dict) -> "list[str]":
        """Turns one raw command-execution entry into a list of finding messages.

        Execution errors (returncode is None, e.g. timeout or missing binary) always
        surface as a finding regardless of result_mode: fail-visible instead of
        fail-silent, so a broken check can't silently pass the build.
        """
        if entry.get("returncode") is None:
            stderr = entry.get("stderr") or "unknown execution error"
            return [f"Rule '{entry.get('rule_id')}' could not be executed: {stderr}"]

        result_mode = entry.get("result_mode", "output_lines")
        stdout = entry.get("stdout", "") or ""

        if result_mode == "exit_code":
            if entry.get("returncode") != 0:
                return [
                    f"Rule '{entry.get('rule_id')}' failed with exit code {entry.get('returncode')}"
                ]
            return []

        if result_mode == "json_stdout":
            if not stdout.strip():
                return []
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                return [f"Invalid JSON output for rule '{entry.get('rule_id')}'"]
            if not isinstance(parsed, list):
                return []
            return [
                item.get("message", "unknown")
                for item in parsed
                if isinstance(item, dict)
            ]

        # default: "output_lines" - one finding per non-empty stdout line
        return [line for line in stdout.splitlines() if line.strip()]

    @classmethod
    def get_list_finding(
        cls,
        results_scan_list: list,
        default_severity: str,
        rules_config: dict = None,
    ) -> "list[Finding]":
        rules_lookup = {}
        for rule_group in (rules_config or {}).values():
            for rule_id, rule_data in rule_group.items():
                rules_lookup[rule_id] = rule_data

        list_open_findings = []

        for entry in results_scan_list:
            rule_id = entry.get("rule_id", "unknown")
            folder = entry.get("folder", "unknown")
            rule_meta = rules_lookup.get(rule_id, {})
            severity = rule_meta.get("severity", default_severity).lower()

            for message in cls.extract_messages(entry):
                finding_open = Finding(
                    id=rule_id,
                    cvss=None,
                    where=f"{folder}: {message}",
                    description=rule_meta.get("description", message),
                    severity=severity,
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    published_date_cve=None,
                    module="engine_scripts",
                    category=Category.VULNERABILITY,
                    requirements=rule_meta.get("guideline"),
                    tool="Script",
                )
                list_open_findings.append(finding_open)

        return list_open_findings
