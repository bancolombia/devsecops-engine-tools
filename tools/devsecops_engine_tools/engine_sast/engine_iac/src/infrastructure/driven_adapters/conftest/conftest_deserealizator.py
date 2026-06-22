from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ConftestDeserealizator:
    @classmethod
    def get_list_finding(
        cls, results_scan_list: list, default_severity: str, default_category: str, rules_config: dict = None
    ) -> "list[Finding]":
        rules_lookup = {}
        for rule_group in (rules_config or {}).values():
            for rule_id, rule_data in rule_group.items():
                rules_lookup[rule_id] = rule_data

        list_open_findings = []

        for file_result in results_scan_list:
            filename = file_result.get("filename", "unknown")

            for failure in file_result.get("failures", []) or []:
                msg = failure.get("msg", "unknown")
                metadata = failure.get("metadata", {}) or {}
                query = metadata.get("query", "unknown")
                node_type = metadata.get("node_type")
                node_id = metadata.get("node_id")
                where = f"{filename}: {node_type}.{node_id}" if node_type and node_id else filename

                rule_id = metadata.get("id", "")
                rule_meta = rules_lookup.get(rule_id, {})

                severity = rule_meta.get("severity", default_severity).lower()
                category_str = rule_meta.get("category", default_category).lower()

                finding_open = Finding(
                    id=rule_id or query,
                    cvss=None,
                    where=where,
                    description=msg,
                    severity=severity,
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    published_date_cve=None,
                    module="engine_iac",
                    category=Category(category_str),
                    requirements=rule_meta.get("url"),
                    tool="Conftest",
                )
                list_open_findings.append(finding_open)

        return list_open_findings
