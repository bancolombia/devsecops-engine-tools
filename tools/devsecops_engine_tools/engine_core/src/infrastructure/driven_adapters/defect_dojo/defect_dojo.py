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
    Product,
    Component,
    FindingExclusion
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.report import Report
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsExcepted,
    ExceptionGettingFindings,
    ExceptionGettingEngagements,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    format_date,
)
from functools import partial

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.serializers.import_scan import (
    ImportScanSerializer,
)
import time
import concurrent.futures

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class DefectDojoPlatform(VulnerabilityManagementGateway):

    RISK_ACCEPTED = "Risk Accepted"
    OUT_OF_SCOPE = "Out of Scope"
    FALSE_POSITIVE = "False Positive"
    TRANSFERRED_FINDING = "Transferred Finding"
    ON_WHITELIST = "On Whitelist"

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
                "DEPENDENCY_CHECK": "Dependency Check Scan",
                "SONARQUBE": "SonarQube API Import",
                "GITLEAKS": "Gitleaks Scan"
            }

            if any(
                branch in str(vulnerability_management.branch_tag)
                for branch in vulnerability_management.config_tool[
                    "VULNERABILITY_MANAGER"
                ]["BRANCH_FILTER"]
            ) or (vulnerability_management.dict_args["tool"] == "engine_secret"):
                tags = vulnerability_management.dict_args["tool"]
                if vulnerability_management.dict_args["tool"] == "engine_iac":
                    tags = f"{vulnerability_management.dict_args['tool']}_{'_'.join(vulnerability_management.dict_args['platform'])}"

                use_cmdb = vulnerability_management.config_tool[
                    "VULNERABILITY_MANAGER"
                ]["DEFECT_DOJO"]["CMDB"]["USE_CMDB"]

                request = self._build_request_importscan(
                    vulnerability_management,
                    token_cmdb,
                    token_dd,
                    scan_type_mapping,
                    enviroment_mapping,
                    tags,
                    use_cmdb,
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

    def get_product_type_service(self, service, dict_args, secret_tool, config_tool):
        try:
            session_manager = self._get_session_manager(
                dict_args, secret_tool, config_tool
            )

            dd_max_retries = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "MAX_RETRIES_QUERY"
            ]

            def request_func():
                response = Product.get_product(
                    session=session_manager,
                    request={
                        "name": Connect.get_code_app(
                            service,
                            config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB"][
                                "REGEX_EXPRESSION_CMDB"
                            ],
                        ),
                        "prefetch": "prod_type",
                    },
                )
                return (
                    response.prefetch.prod_type[str(response.results[0].prod_type)]
                    if response.prefetch
                    else None
                )

            return self._retries_requests(request_func, dd_max_retries, retry_delay=5)

        except Exception as ex:
            raise ExceptionVulnerabilityManagement(
                "Error getting product type with the following error: {0} ".format(ex)
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
            out_of_scope_query_params = {
                "out_of_scope": True,
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
            white_list_query_params = {
                "risk_status": self.ON_WHITELIST,
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
                self.RISK_ACCEPTED,
            )

            exclusions_false_positive = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                false_positive_query_params,
                tool,
                self._format_date_to_dd_format,
                self.FALSE_POSITIVE,
            )

            exclusions_out_of_scope = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                out_of_scope_query_params,
                tool,
                self._format_date_to_dd_format,
                self.OUT_OF_SCOPE,
            )

            exclusions_transfer_finding = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                transfer_finding_query_params,
                tool,
                self._format_date_to_dd_format,
                self.TRANSFERRED_FINDING,
            )

            white_list = self._get_finding_exclusion(
                session_manager, dd_max_retries, {
                    "type": "white_list",
                }
            )

            exclusions_white_list = self._get_findings_with_exclusions(
                session_manager,
                service,
                dd_max_retries,
                white_list_query_params,
                tool,
                self._format_date_to_dd_format,
                self.ON_WHITELIST,
                white_list=white_list,
            )

            return (
                list(exclusions_risk_accepted)
                + list(exclusions_false_positive)
                + list(exclusions_out_of_scope)
                + list(exclusions_transfer_finding)
                + list(exclusions_white_list)
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
                ],
                "duplicate": "false",
            }
            max_retries = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "MAX_RETRIES_QUERY"
            ]
            host_dd = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "HOST_DEFECT_DOJO"
            ]

            session_manager = self._get_session_manager(dict_args, secret_tool, config_tool)

            findings = self._get_findings(
                session_manager,
                service,
                max_retries,
                all_findings_query_params,
            )

            all_findings = list(
                map(
                    partial(self._create_report, host_dd=host_dd),
                    findings,
                )
            )

            white_list = self._get_finding_exclusion(
                session_manager, max_retries, {
                    "type": "white_list",
                }
            )

            all_exclusions = self._get_report_exclusions(
                all_findings, self._format_date_to_dd_format, host_dd=host_dd, white_list=white_list
            )

            return all_findings, all_exclusions

        except Exception as ex:
            raise ExceptionGettingFindings(
                "Error getting all findings with the following error: {0} ".format(ex)
            )

    def get_active_engagements(
        self, engagement_name, dict_args, secret_tool, config_tool
    ):
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

            engagements = Engagement.get_engagements(request_is, request_active).results

            host_dd = config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                "HOST_DEFECT_DOJO"
            ]

            for engagement in engagements:
                engagement.vm_url = f"{host_dd}/engagement/{engagement.id}/finding/open"

            return engagements

        except Exception as ex:
            raise ExceptionGettingEngagements(
                "Error getting engagements with the following error: {0} ".format(ex)
            )

    def send_sbom_components(
        self, sbom_components, service, dict_args, secret_tool, config_tool
    ):
        try:
            engagements = self.get_active_engagements(
                service, dict_args, secret_tool, config_tool
            )
            engagement = [
                engagement for engagement in engagements if engagement.name == service
            ]
            session_manager = self._get_session_manager(
                dict_args, secret_tool, config_tool
            )

            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                _ = [
                    executor.submit(
                        self._process_component,
                        sbom_component,
                        session_manager,
                        engagement,
                    )
                    for sbom_component in sbom_components
                ]

        except Exception as ex:
            raise ExceptionVulnerabilityManagement(
                "Error sending components sbom to vulnerability management with the following error: {0} ".format(
                    ex
                )
            )

    def _build_request_importscan(
        self,
        vulnerability_management: VulnerabilityManagement,
        token_cmdb,
        token_dd,
        scan_type_mapping,
        enviroment_mapping,
        tags,
        use_cmdb: bool,
    ):
        common_fields = {
            "scan_type": scan_type_mapping[vulnerability_management.scan_type],
            "file": vulnerability_management.input_core.path_file_results,
            "engagement_name": vulnerability_management.input_core.scope_pipeline,
            "source_code_management_uri": vulnerability_management.source_code_management_uri,
            "tags": tags,
            "version": vulnerability_management.version,
            "build_id": vulnerability_management.build_id,
            "branch_tag": vulnerability_management.branch_tag,
            "commit_hash": vulnerability_management.commit_hash,
            "service": vulnerability_management.input_core.scope_pipeline,
            "environment": (
                enviroment_mapping[vulnerability_management.environment.lower()]
                if vulnerability_management.environment is not None
                and vulnerability_management.environment.lower() in enviroment_mapping
                else enviroment_mapping["default"]
            ),
            "token_defect_dojo": token_dd,
            "host_defect_dojo": vulnerability_management.config_tool[
                "VULNERABILITY_MANAGER"
            ]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
            "expression": vulnerability_management.config_tool["VULNERABILITY_MANAGER"][
                "DEFECT_DOJO"
            ]["CMDB"]["REGEX_EXPRESSION_CMDB"],
        }

        if use_cmdb:
            cmdb_mapping = vulnerability_management.config_tool[
                "VULNERABILITY_MANAGER"
            ]["DEFECT_DOJO"]["CMDB"]["CMDB_MAPPING"]
            return Connect.cmdb(
                cmdb_mapping={
                    "product_type_name": cmdb_mapping["PRODUCT_TYPE_NAME"],
                    "product_name": cmdb_mapping["PRODUCT_NAME"],
                    "tag_product": cmdb_mapping["TAG_PRODUCT"],
                    "product_description": cmdb_mapping["PRODUCT_DESCRIPTION"],
                    "codigo_app": cmdb_mapping["CODIGO_APP"],
                },
                compact_remote_config_url=f'{vulnerability_management.base_compact_remote_config_url}{vulnerability_management.config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB"]["CMDB_MAPPING_PATH"]}',
                personal_access_token=vulnerability_management.access_token,
                token_cmdb=token_cmdb,
                host_cmdb=vulnerability_management.config_tool["VULNERABILITY_MANAGER"][
                    "DEFECT_DOJO"
                ]["CMDB"]["HOST_CMDB"],
                cmdb_request_response=vulnerability_management.config_tool[
                    "VULNERABILITY_MANAGER"
                ]["DEFECT_DOJO"]["CMDB"]["CMDB_REQUEST_RESPONSE"],
                **common_fields,
            )
        else:
            request: ImportScanRequest = ImportScanSerializer().load(
                {
                    "product_type_name": vulnerability_management.vm_product_type_name,
                    "product_name": vulnerability_management.vm_product_name,
                    "product_description": vulnerability_management.vm_product_description,
                    "code_app": vulnerability_management.vm_product_name,
                    **common_fields,
                }
            )
            return request

    def _process_component(self, component_sbom, session_manager, engagement):
        request = {
            "name": component_sbom.name,
            "version": component_sbom.version,
            "engagement_id": engagement[0].id,
        }
        components = Component.get_component(session=session_manager, request=request)
        if components.results == []:
            response = Component.create_component(
                session=session_manager, request=request
            )
            logger.info(
                f"Component created: {response.name} - {response.version} found with id: {response.id}"
            )

    def _get_session_manager(self, dict_args, secret_tool, config_tool):
        token_dd = dict_args.get("token_vulnerability_management") or secret_tool.get(
            "token_defect_dojo"
        )
        return SessionManager(
            token_dd,
            config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
        )

    def _get_report_exclusions(self, total_findings, date_fn, host_dd, **kwargs):
        exclusions = []
        for finding in total_findings:
            if finding.risk_accepted:
                exclusions.append(
                    self._create_report_exclusion(
                        finding, date_fn, "engine_risk", self.RISK_ACCEPTED, host_dd, **kwargs
                    )
                )
            elif finding.false_p:
                exclusions.append(
                    self._create_report_exclusion(
                        finding, date_fn, "engine_risk", self.FALSE_POSITIVE, host_dd, **kwargs
                    )
                )
            elif finding.out_of_scope:
                exclusions.append(
                    self._create_report_exclusion(
                        finding, date_fn, "engine_risk", self.OUT_OF_SCOPE, host_dd, **kwargs
                    )
                )
            elif finding.risk_status == "Transfer Accepted":
                exclusions.append(
                    self._create_report_exclusion(
                        finding,
                        date_fn,
                        "engine_risk",
                        self.TRANSFERRED_FINDING,
                        host_dd,
                        **kwargs
                    )
                )
            elif finding.risk_status == self.ON_WHITELIST:
                exclusions.append(
                    self._create_report_exclusion(
                        finding, date_fn, "engine_risk", self.ON_WHITELIST, host_dd, **kwargs
                    )
                )
        return exclusions

    def _get_findings_with_exclusions(
        self, session_manager, service, max_retries, query_params, tool, date_fn, reason, **kwargs
    ):
        findings = self._get_findings(
            session_manager, service, max_retries, query_params
        )

        return map(
            partial(self._create_exclusion, date_fn=date_fn, tool=tool, reason=reason, **kwargs),
            findings,
        )

    def _get_findings(self, session_manager, service, max_retries, query_params):
        def request_func():
            return Finding.get_finding(
                session=session_manager, service=service, **query_params
            ).results

        return self._retries_requests(request_func, max_retries, retry_delay=5)
    
    def _get_finding_exclusion(self, session_manager, max_retries, query_params):
        def request_func():
            return FindingExclusion.get_finding_exclusion(
                session=session_manager, **query_params
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


    def _date_reason_based(self, finding, date_fn, reason, tool, **kwargs):
        def get_vuln_id(finding, tool):
            if tool == "engine_risk":
                return finding.id[0]["vulnerability_id"] if finding.id else finding.vuln_id_from_tool
            else:
                return finding.vulnerability_ids[0]["vulnerability_id"] if finding.vulnerability_ids else finding.vuln_id_from_tool

        def get_dates_from_whitelist(vuln_id, white_list):
            matching_finding = next(filter(lambda x: x.unique_id_from_tool == vuln_id, white_list), None)
            if matching_finding:
                return date_fn(matching_finding.create_date), date_fn(matching_finding.expiration_date)
            return date_fn(None), date_fn(None)

        reason_to_dates = {
            self.FALSE_POSITIVE: lambda: (date_fn(finding.last_status_update), date_fn(None)),
            self.OUT_OF_SCOPE: lambda: (date_fn(finding.last_status_update), date_fn(None)),
            self.TRANSFERRED_FINDING: lambda: (date_fn(finding.transfer_finding.date), date_fn(finding.transfer_finding.expiration_date)),
            self.RISK_ACCEPTED: lambda: (date_fn(finding.accepted_risks[-1]["created"]), date_fn(finding.accepted_risks[-1]["expiration_date"])),
            self.ON_WHITELIST: lambda: get_dates_from_whitelist(get_vuln_id(finding, tool), kwargs.get("white_list", [])),
        }

        create_date, expired_date = reason_to_dates.get(reason, lambda: (date_fn(None), date_fn(None)))()
        return create_date, expired_date

    def _create_exclusion(self, finding, date_fn, tool, reason, **kwargs):
        create_date, expired_date = self._date_reason_based(finding, date_fn, reason, tool, **kwargs)
            
        return Exclusions(
            id=(
                finding.vuln_id_from_tool
                if finding.vuln_id_from_tool
                else (
                    finding.vulnerability_ids[0]["vulnerability_id"]
                    if finding.vulnerability_ids
                    else ""
                )
            ),
            where=self._get_where(finding, tool),
            create_date=create_date,
            expired_date=expired_date,
            severity=finding.severity,
            reason=reason,
        )

    def _create_report_exclusion(self, finding, date_fn, tool, reason, host_dd, **kwargs):
        create_date, expired_date = self._date_reason_based(finding, date_fn, reason, tool, **kwargs)

        return Exclusions(
            id=(
                finding.vuln_id_from_tool
                if finding.vuln_id_from_tool
                else finding.id[0]["vulnerability_id"] if finding.id else ""
            ),
            where=self._get_where(finding, tool),
            create_date=create_date,
            expired_date=expired_date,
            severity=finding.severity,
            reason=reason,
            vm_id=str(finding.vm_id),
            vm_id_url=f"{host_dd}/finding/{finding.vm_id}",
            service=finding.service,
            tags=finding.tags,
        )

    def _create_report(self, finding, host_dd):
        return Report(
            vm_id=str(finding.id),
            vm_id_url=f"{host_dd}/finding/{finding.id}",
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
            out_of_scope=finding.out_of_scope,
            service=finding.service,
            unique_id_from_tool=finding.unique_id_from_tool,
        )

    def _format_date_to_dd_format(self, date_string):
        return (
            format_date(date_string.split("T")[0], "%Y-%m-%d", "%d%m%Y")
            if date_string
            else None
        )

    def _get_where(self, finding, tool):
        if tool == "engine_dependencies":
            return (
                finding.component_name.replace("_", ":")
                + ":"
                + finding.component_version
            )
        elif tool == "engine_container":
            return finding.component_name + ":" + finding.component_version
        elif tool == "engine_dast":
            return finding.endpoints
        elif tool == "engine_risk":
            for tag in finding.tags:
                return self._get_where(finding, tag)
            return finding.file_path
        else:
            return finding.file_path
