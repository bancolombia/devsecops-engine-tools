from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.context_iac import ContextIac
from abc import ABCMeta, abstractmethod
import json
import logging

logger = logging.getLogger(__name__)

class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool(self, config_tool, folders_to_scan, **kwargs):
        "run_tool"

    @classmethod
    def get_iac_context_from_results(
        cls, context_results_scan_list: list, rules, default_severity
    ) -> None:

        context_iac_list = []
        for result in context_results_scan_list:
            if "failed_checks" in str(result):                
                for check in result["results"]["failed_checks"]:
                    check_id = check.get("check_id")
                    rule_info = rules.get(check_id, {})
                    severity = rule_info.get("severity", default_severity).lower()
                    file_line_range = check.get("file_line_range", ["unknown", "unknown"])
                    start_line = file_line_range[0] if len(file_line_range) > 0 else "unknown"
                    end_line = file_line_range[1] if len(file_line_range) > 1 else "unknown"
                    line_range_str = f"{start_line}-{end_line}" if start_line != end_line else str(start_line)

                    context_iac = ContextIac(
                        id=check.get("check_id", "unknown"),
                        check_name=check.get("check_name", "unknown"),
                        check_class=check.get("check_class", "unknown"),
                        severity=severity,
                        where=f"{check.get('repo_file_path', 'unknown')}: {check.get('resource', 'unknown')} (line {line_range_str})",
                        resource=check.get("resource", "unknown"),
                        description=check.get("check_name", "unknown"),
                        module="engine_iac",
                        tool="Checkov"
                    )

                    context_iac_list.append(context_iac)
                           
        logger.info("===== BEGIN CONTEXT OUTPUT =====")
        logger.info(json.dumps({"iac_context": [obj.__dict__ for obj in context_iac_list]}, indent=4))
        logger.info("===== END CONTEXT OUTPUT =====")