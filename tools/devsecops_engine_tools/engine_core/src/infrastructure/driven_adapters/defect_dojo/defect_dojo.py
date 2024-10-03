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
    Engagement,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.report import Report
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsExcepted,
    ExceptionGettingFindings,
    ExceptionGettingEngagements
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    format_date,
)
from functools import partial

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
import time

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


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
                "KUBESCAPE": "Kubescape Scanner",
                "KICS": "KICS Scanner",
                "BEARER": "Bearer CLI",
                "DEPENDENCY_CHECK": "Dependency Check Scan"
            }

            if any(
                branch in str(vulnerability_management.branch_tag)
                for branch in vulnerability_management.config_tool[
                    "VULNERABILITY_MANAGER"
                ]["BRANCH_FILTER"].split(",")
            ) or (vulnerability_management.dict_args["tool"] == "engine_secret"):
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

                def request_func():
                    return DefectDojo.send_import_scan(request)

                response = self._retries_requests(
                    request_func,
                    vulnerability_management.config_tool["VULNERABILITY_MANAGER"][
                        "DEFECT_DOJO"
                    ]["MAX_RETRIES_QUERY"],
                    retry_delay=5,
                )

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
            session_manager = self._get_session_manager(
                dict_args, secret_tool, config_tool
            )

            dd_limits_query = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "LIMITS_QUERY"
            ]
            dd_max_retries = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "MAX_RETRIES_QUERY"
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
            transfer_finding_query_params = {
                "risk_status": "Transfer Accepted",
                "tags": tool,
                "limit": dd_limits_query,
            }

            exclusions_risk_accepted = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                risk_accepted_query_params,
                tool,
                self._format_date_to_dd_format,
                "Risk Accepted",
            )

            exclusions_false_positive = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                false_positive_query_params,
                tool,
                self._format_date_to_dd_format,
                "False Positive",
            )

            exclusions_transfer_finding = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                transfer_finding_query_params,
                tool,
                self._format_date_to_dd_format,
                "Transferred Finding",
            )

            return (
                list(exclusions_risk_accepted)
                + list(exclusions_false_positive)
                + list(exclusions_transfer_finding)
            )
        except Exception as ex:
            raise ExceptionFindingsExcepted(
                "Error getting excepted findings with the following error: {0} ".format(
                    ex
                )
            )

    def get_all(self, service, dict_args, secret_tool, config_tool):
        try:
            all_findings_query_params = {
                "limit": config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                    "LIMITS_QUERY"
                ]
            }
            max_retries = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "MAX_RETRIES_QUERY"
            ]

            findings = self._get_findings(
                self._get_session_manager(dict_args, secret_tool, config_tool),
                service,
                max_retries,
                all_findings_query_params,
            )

            all_findings = list(
                map(
                    partial(self._create_report),
                    findings,
                )
            )

            all_exclusions = self._get_report_exclusions(
                all_findings, self._format_date_to_dd_format
            )

            return all_findings, all_exclusions

        except Exception as ex:
            raise ExceptionGettingFindings(
                "Error getting all findings with the following error: {0} ".format(ex)
            )

    def get_active_engagements(self, engagement_name, dict_args, secret_tool, config_tool):
        try:
            request_is = ImportScanRequest(
                token_defect_dojo=dict_args.get("token_vulnerability_management")
                or secret_tool.get("token_defect_dojo"),
                host_defect_dojo=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                    "HOST_DEFECT_DOJO"
                ],
                engagement_name=engagement_name,
            )

            request_active = {
                "name": engagement_name,
                "limit": config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                    "LIMITS_QUERY"
                ],
                "active": "true",
            }

            return Engagement.get_engagements(request_is, request_active).results

        except Exception as ex:
            raise ExceptionGettingEngagements(
                "Error getting engagements with the following error: {0} ".format(ex)
            )

    def _get_session_manager(self, dict_args, secret_tool, config_tool):
        token_dd = dict_args.get("token_vulnerability_management") or secret_tool.get(
            "token_defect_dojo"
        )
        return SessionManager(
            token_dd,
            config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
        )

    def _get_report_exclusions(self, total_findings, date_fn):
        exclusions = []
        for finding in total_findings:
            if finding.risk_accepted:
                exclusions.append(
                    self._create_exclusion(
                        finding, date_fn, "engine_risk", "Risk Accepted"
                    )
                )
            elif finding.false_p:
                exclusions.append(
                    self._create_exclusion(
                        finding, date_fn, "engine_risk", "False Positive"
                    )
                )
            elif finding.risk_status == "Transfer Accepted":
                exclusions.append(
                    self._create_exclusion(
                        finding, date_fn, "engine_risk", "Transferred Finding"
                    )
                )
        return exclusions

    def _get_findings_with_exclusions(
        self, session_manager, service, max_retries, query_params, tool, date_fn, reason
    ):
        findings = self._get_findings(
            session_manager, service, max_retries, query_params
        )
        return map(
            partial(self._create_exclusion, date_fn=date_fn, tool=tool, reason=reason),
            findings,
        )

    def _get_findings(self, session_manager, service, max_retries, query_params):
        def request_func():
            return Finding.get_finding(
                session=session_manager, service=service, **query_params
            ).results

        return self._retries_requests(request_func, max_retries, retry_delay=5)

    def _retries_requests(self, request_func, max_retries, retry_delay):
        for attempt in range(max_retries):
            try:
                return request_func()
            except Exception as e:
                logger.error(f"Error making the request: {e}")
                if attempt < max_retries - 1:
                    logger.warning(f"Retry in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("Maximum number of retries reached, aborting.")
                    raise e

    def _create_exclusion(self, finding, date_fn, tool, reason):
        if reason == "False Positive":
            create_date = date_fn(finding.last_status_update)
            expired_date = date_fn(None)
        elif reason == "Transferred Finding":
            create_date = date_fn(finding.transfer_finding.date)
            expired_date = date_fn(finding.transfer_finding.expiration_date)
        else:
            last_accepted_risk = finding.accepted_risks[-1]
            create_date = date_fn(last_accepted_risk["created"])
            expired_date = date_fn(last_accepted_risk["expiration_date"])

        return Exclusions(
            id=finding.vuln_id_from_tool,
            where=self._get_where(finding, tool),
            create_date=create_date,
            expired_date=expired_date,
            severity=finding.severity,
            reason=reason,
        )

    def _create_report(self, finding):
        return Report(
            id=finding.vulnerability_ids,
            vuln_id_from_tool=finding.vuln_id_from_tool,
            status=finding.display_status,
            component_name=finding.component_name,
            component_version=finding.component_version,
            file_path=finding.file_path,
            endpoints=finding.endpoints,
            where=self._get_where(finding, "engine_risk"),
            tags=finding.tags,
            severity=finding.severity,
            age=finding.age,
            active=finding.active,
            risk_status=finding.risk_status,
            created=finding.created,
            publish_date=finding.publish_date,
            last_reviewed=finding.last_reviewed,
            last_status_update=finding.last_status_update,
            accepted_risks=finding.accepted_risks,
            transfer_finding=finding.transfer_finding,
            epss_score=finding.epss_score,
            epss_percentile=finding.epss_percentile,
            mitigated=finding.is_mitigated,
            vul_description=finding.description,
            risk_accepted=finding.risk_accepted,
            false_p=finding.false_p,
            service=finding.service,
        )

    def _format_date_to_dd_format(self, date_string):
        return (
            format_date(date_string.split("T")[0], "%Y-%m-%d", "%d%m%Y")
            if date_string
            else None
        )

    def _get_where(self, finding, tool):
        if tool in ["engine_container", "engine_dependencies"]:
            return finding.component_name + ":" + finding.component_version
        elif tool == "engine_dast":
            return finding.endpoints
        elif tool == "engine_risk":
            for tag in finding.tags:
                return self._get_where(finding, tag)
        else:
            return finding.file_path
