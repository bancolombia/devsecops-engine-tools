from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement,
)
from devsecops_engine_tools.engine_utilities.defect_dojo import (
    DefectDojo,
    ImportScanRequest,
    Connect,
    Finding,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.report import Report
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsExcepted,
    ExceptionGettingFindings,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    format_date,
)
from functools import partial


@dataclass
class DefectDojoPlatform(VulnerabilityManagementGateway):
    def send_vulnerability_management(
        self, vulnerability_management: VulnerabilityManagement
    ):
        try:
            token_dd = (
                vulnerability_management.dict_args["token_vulnerability_management"]
                if vulnerability_management.dict_args["token_vulnerability_management"]
                is not None
                else vulnerability_management.secret_tool["token_defect_dojo"]
            )
            token_cmdb = (
                vulnerability_management.dict_args["token_cmdb"]
                if vulnerability_management.dict_args["token_cmdb"] is not None
                else vulnerability_management.secret_tool["token_cmdb"]
            )

            enviroment_mapping = {
                "dev": "Development",
                "qa": "Staging",
                "pdn": "Production",
                "default": "Production",
            }
            scan_type_mapping = {
                "CHECKOV": "Checkov Scan",
                "PRISMA": "Twistlock Image Scan",
                "XRAY": "JFrog Xray On Demand Binary Scan",
                "TRUFFLEHOG": "Trufflehog Scan",
                "TRIVY": "Trivy Scan",
            }

            if any(
                branch in str(vulnerability_management.branch_tag)
                for branch in vulnerability_management.config_tool[
                    "VULNERABILITY_MANAGER"
                ]["BRANCH_FILTER"].split(",")
            ) or (vulnerability_management.dict_args["tool"] == 'engine_secret'):
                request: ImportScanRequest = Connect.cmdb(
                    cmdb_mapping={
                        "product_type_name": "nombreevc",
                        "product_name": "nombreapp",
                        "tag_product": "nombreentorno",
                        "product_description": "arearesponsableti",
                        "codigo_app": "CodigoApp",
                    },
                    compact_remote_config_url=f'{vulnerability_management.base_compact_remote_config_url}{vulnerability_management.config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB_MAPPING_PATH"]}',
                    personal_access_token=vulnerability_management.access_token,
                    token_cmdb=token_cmdb,
                    host_cmdb=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["HOST_CMDB"],
                    expression=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["REGEX_EXPRESSION_CMDB"],
                    token_defect_dojo=token_dd,
                    host_defect_dojo=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
                    scan_type=scan_type_mapping[vulnerability_management.scan_type],
                    engagement_name=vulnerability_management.input_core.scope_pipeline,
                    service=vulnerability_management.input_core.scope_pipeline,
                    file=vulnerability_management.input_core.path_file_results,
                    version=vulnerability_management.version,
                    build_id=vulnerability_management.build_id,
                    source_code_management_uri=vulnerability_management.source_code_management_uri,
                    branch_tag=vulnerability_management.branch_tag,
                    commit_hash=vulnerability_management.commit_hash,
                    environment=(
                        enviroment_mapping[vulnerability_management.environment.lower()]
                        if vulnerability_management.environment is not None
                        and vulnerability_management.environment.lower()
                        in enviroment_mapping
                        else enviroment_mapping["default"]
                    ),
                    tags=vulnerability_management.dict_args["tool"],
                )

                response = DefectDojo.send_import_scan(request)
                if hasattr(response, "url"):
                    url_parts = response.url.split("//")
                    test_string = "//".join([url_parts[0] + "/", url_parts[1]])
                    print(
                        "Report sent to vulnerability management: ",
                        f"{test_string}?tags={vulnerability_management.dict_args['tool']}",
                    )
                else:
                    raise ExceptionVulnerabilityManagement(response)
        except Exception as ex:
            raise ExceptionVulnerabilityManagement(
                "Error sending report to vulnerability management with the following error: {0} ".format(
                    ex
                )
            )

    def get_findings_excepted(self, service, dict_args, secret_tool, config_tool):
        try:
            session_manager = self._get_session_manager(dict_args, secret_tool, config_tool)

            dd_limits_query = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "LIMITS_QUERY"
            ]
            tool = dict_args["tool"]

            risk_accepted_query_params = {
                "risk_accepted": True,
                "tags": tool,
                "limit": dd_limits_query,
            }
            false_positive_query_params = {
                "false_p": True,
                "tags": tool,
                "limit": dd_limits_query,
            }

            exclusions_risk_accepted = self._get_findings_with_exclusions(
                session_manager,
                service,
                risk_accepted_query_params,
                tool,
                self._format_date_to_dd_format,
                "Risk Accepted",
            )

            exclusions_false_positive = self._get_findings_with_exclusions(
                session_manager,
                service,
                false_positive_query_params,
                tool,
                self._format_date_to_dd_format,
                "False Positive",
            )

            return list(exclusions_risk_accepted) + list(exclusions_false_positive)
        except Exception as ex:
            raise ExceptionFindingsExcepted(
                "Error getting excepted findings with the following error: {0} ".format(
                    ex
                )
            )

    def get_all_findings(
        self, service, dict_args, secret_tool, config_tool
    ):
        try:
            all_findings_query_params = {
                "limit": config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["LIMITS_QUERY"]
            }

            findings = self._get_findings(
                self._get_session_manager(dict_args, secret_tool, config_tool),
                service, 
                all_findings_query_params
            )

            maped_list = list(
                map(
                    partial(self._create_report, date_fn=self._format_date_to_dd_format),
                    findings,
                )
            )

            return maped_list

        except Exception as ex:
            raise ExceptionGettingFindings(
                "Error getting all findings with the following error: {0} ".format(
                    ex
                )
            )

    def _get_session_manager(self, dict_args, secret_tool, config_tool):
        token_dd = dict_args.get(
                "token_vulnerability_management"
            ) or secret_tool.get("token_defect_dojo")
        return SessionManager(
            token_dd,
            config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
        )

    def _get_findings_with_exclusions(
        self, session_manager, service, query_params, tool, date_fn, reason
    ):
        findings = self._get_findings(session_manager, service, query_params)
        return map(
            partial(self._create_exclusion, date_fn=date_fn, tool=tool, reason=reason),
            findings,
        )

    def _get_findings(self, session_manager, service, query_params):
        return Finding.get_finding(
            session=session_manager, service=service, **query_params
        ).results

    def _create_exclusion(self, finding, date_fn, tool, reason):
        return Exclusions(
            id=finding.vuln_id_from_tool,
            where=self._get_where(finding, tool),
            create_date=date_fn(
                finding.last_status_update
                if reason == "False Positive"
                else finding.accepted_risks[-1]["created"]
            ),
            expired_date=date_fn(
                None
                if reason == "False Positive"
                else finding.accepted_risks[-1]["expiration_date"]
            ),
            reason=reason,
        )

    def _create_report(self, finding, date_fn):
        return Report(
            id=finding.vuln_id_from_tool,
            date=date_fn(
                finding.date
            ),
            status=finding.display_status,
            where=self._get_where_report(finding),
            tags=finding.tags,
            severity=finding.severity,
            active=finding.active,
        )

    def _format_date_to_dd_format(self, date_string):
        return (
            format_date(date_string.split("T")[0], "%Y-%m-%d", "%d%m%Y")
            if date_string
            else None
        )
    
    def _get_where_report(self, finding):
        for tag in finding.tags:
            return self._get_where(finding, tag)

    def _get_where(self, finding, tool):
        if tool in ["engine_container", "engine_dependencies"]:
            return finding.component_name + ":" + finding.component_version
        elif tool == "engine_dast":
            return finding.endpoints
        else:
            return finding.file_path
