from devsecops_engine_tools.engine_core.src.domain.model.gateway.license_manager import LicenseManagerGateway
from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.applications.runner_secret_scan import (
    runner_secret_scan,
)
from devsecops_engine_tools.engine_sast.engine_code.src.applications.runner_engine_code import (
    runner_engine_code,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.risk_score_gateway import (
    RiskScoreGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.context_extraction_gateway import (
    ContextExtractionGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.level_vulnerability import (
    LevelVulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.level_priority import (
    LevelPriority,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsExcepted,
)
from devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan import (
    runner_engine_container,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.applications.runner_dependencies_scan import (
    runner_engine_dependencies,
)
from devsecops_engine_tools.engine_sca.engine_license.src.applications.runner_license_scan import (
    runner_engine_license,
)
from devsecops_engine_tools.engine_sca.engine_license.src.infrastructure.driven_adapters.license_scan.license_scan_manager import (
    LicenseScanManager,
)
from devsecops_engine_tools.engine_sca.engine_function.src.applications.runner_function_scan import (
    runner_engine_function,
)
from devsecops_engine_tools.engine_dast.src.applications.runner_dast_scan import (
    runner_engine_dast,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    define_env,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class HandleScan:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        sbom_tool_gateway: SbomManagerGateway,
        risk_score_gateway: RiskScoreGateway,
        context_extraction_gateway: ContextExtractionGateway,
        license_tool_gateway: LicenseManagerGateway,
    ):
        self.vulnerability_management = vulnerability_management
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.sbom_tool_gateway = sbom_tool_gateway
        self.risk_score_gateway = risk_score_gateway
        self.context_extraction_gateway = context_extraction_gateway
        self.license_tool_gateway = license_tool_gateway
    
    def process(self, dict_args: any, config_tool: any):
        secret_tool = None
        env = define_env(
            self.devops_platform_gateway.get_variable("environment"),
            self.devops_platform_gateway.get_variable("branch_name"),
        )
        if dict_args["use_secrets_manager"] == "true":
            secret_tool = self.secrets_manager_gateway.get_secret(config_tool)
        if "engine_iac" in dict_args["module"]:
            findings_list, input_core, tool_gateway = runner_engine_iac(
                dict_args,
                config_tool["ENGINE_IAC"]["TOOL"],
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway,
                env,
            )
            
            self._handle_context_extraction(
                dict_args,
                "engine_iac",
                input_core.path_file_results,
                config_tool["ENGINE_IAC"],
                tool_gateway,
                config_tool
            )
            
            self._use_vulnerability_management(
                config_tool, input_core, dict_args, secret_tool, env
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_container" in dict_args["module"]:
            findings_list, input_core, sbom_components, tool_gateway = runner_engine_container(
                dict_args,
                config_tool["ENGINE_CONTAINER"]["TOOL"],
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway
            )
            
            self._handle_context_extraction(
                dict_args,
                "engine_container",
                input_core.path_file_results,
                config_tool["ENGINE_CONTAINER"],
                tool_gateway,
                config_tool
            )
            
            self._use_vulnerability_management(
                config_tool,
                input_core,
                dict_args,
                secret_tool,
                env,
                sbom_components,
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_function" in dict_args["module"]:
            findings_list, input_core = runner_engine_function(
                dict_args,
                config_tool["ENGINE_FUNCTION"],
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway
            )
            self._use_vulnerability_management(
                config_tool,
                input_core,
                dict_args,
                secret_tool,
                env
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_dast" in dict_args["module"]:
            findings_list, input_core = runner_engine_dast(
                dict_args,
                config_tool["ENGINE_DAST"],
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway,
            )
            self._use_vulnerability_management(
                config_tool, input_core, dict_args, secret_tool, env
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_code" in dict_args["module"]:
            findings_list, input_core = runner_engine_code(
                dict_args,
                config_tool["ENGINE_CODE"]["TOOL"],
                self.devops_platform_gateway,
                self.remote_config_source_gateway
            )
            self._use_vulnerability_management(
                config_tool, input_core, dict_args, secret_tool, env
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_secret" in dict_args["module"]:
            findings_list, input_core = runner_secret_scan(
                dict_args,
                config_tool["ENGINE_SECRET"]["TOOL"],
                self.devops_platform_gateway,
                self.remote_config_source_gateway,
                secret_tool,
            )
            self._use_vulnerability_management(
                config_tool, input_core, dict_args, secret_tool, env
            )
            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_dependencies" in dict_args["module"]:
            findings_list, input_core, sbom_components, tool_gateway = runner_engine_dependencies(
                dict_args,
                config_tool,
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway,
                self.sbom_tool_gateway,
                self.license_tool_gateway
            )
            
            self._handle_context_extraction(
                dict_args,
                "engine_dependencies",
                input_core.path_file_results,
                config_tool["ENGINE_DEPENDENCIES"],
                tool_gateway,
                config_tool
            )
            
            self._use_vulnerability_management(
                config_tool, input_core, dict_args, secret_tool, env, sbom_components
            )

            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core
        elif "engine_license" in dict_args["module"]:
            findings_list, input_core, _sbom_components = runner_engine_license(
                dict_args,
                config_tool,
                secret_tool,
                self.devops_platform_gateway,
                self.remote_config_source_gateway,
                self.sbom_tool_gateway,
            )

            self._handle_context_extraction(
                dict_args,
                "engine_license",
                input_core.path_file_results,
                config_tool["ENGINE_LICENSE"],
                LicenseScanManager(),
                config_tool
            )

            self.risk_score_gateway.get_risk_score(findings_list, config_tool, dict_args["module"])
            return findings_list, input_core

    def _use_vulnerability_management(
        self,
        config_tool,
        input_core: InputCore,
        dict_args,
        secret_tool,
        env,
        sbom_components=None,
    ):
        if dict_args["use_vulnerability_management"] == "true":
            try:
                if input_core.path_file_results:
                    self.vulnerability_management.send_vulnerability_management(
                        VulnerabilityManagement(
                            config_tool[dict_args["module"].upper()]["TOOL"],
                            input_core,
                            dict_args,
                            secret_tool,
                            config_tool,
                            self.devops_platform_gateway.get_variable("repository_provider"),
                            self.devops_platform_gateway.get_source_code_management_uri(),
                            None,
                            self.devops_platform_gateway.get_variable("access_token"),
                            self.devops_platform_gateway.get_variable(
                                "build_execution_id"
                            ),
                            self.devops_platform_gateway.get_variable("build_id"),
                            self.devops_platform_gateway.get_variable("branch_tag"),
                            self.devops_platform_gateway.get_variable("commit_hash"),
                            env,
                            self.devops_platform_gateway.get_variable(
                                "vm_product_type_name"
                            ),
                            self.devops_platform_gateway.get_variable(
                                "vm_product_name"
                            ),
                            self.devops_platform_gateway.get_variable(
                                "vm_product_description"
                            ),
                        )
                    )

                    branch_filter = [branch for branch in config_tool.get("VULNERABILITY_MANAGER", {}).get("BRANCH_FILTER", []) if branch is not None]
                    if sbom_components and any(
                        branch in str(self.devops_platform_gateway.get_variable("branch_tag"))
                        for branch in branch_filter
                    ):
                        self.vulnerability_management.send_sbom_components(
                            sbom_components,
                            input_core.scope_pipeline,
                            dict_args,
                            secret_tool,
                            config_tool,
                        )

                self._update_threshold_cve(
                    input_core, dict_args, secret_tool, config_tool
                )

                self._define_threshold_quality_vuln(
                    input_core, dict_args, secret_tool, config_tool
                )

            except ExceptionVulnerabilityManagement as ex1:
                logger.error(str(ex1))
            try:
                input_core.totalized_exclusions.extend(
                    self.vulnerability_management.get_findings_excepted(
                        input_core.scope_service,
                        dict_args,
                        secret_tool,
                        config_tool,
                    )
                )
            except ExceptionFindingsExcepted as ex2:
                logger.error(str(ex2))

    def _update_threshold_cve(
        self, input_core: InputCore, dict_args, secret_tool, config_tool
    ):
        if input_core.threshold_defined.name == "default":
            input_core.threshold_defined.cve.extend(
                self.vulnerability_management.get_black_list(
                    dict_args, secret_tool, config_tool
                )
            )

    def _define_threshold_quality_vuln(
        self, input_core: InputCore, dict_args, secret_tool, config_tool
    ):
        quality_vulnerability_management = (
            input_core.threshold_defined.quality_vulnerability_management
        )
        if not (
            quality_vulnerability_management
            and input_core.threshold_defined.name == "default"
        ):
            return

        product_type = self.vulnerability_management.get_product_type_pipeline(
            input_core.scope_pipeline, dict_args, secret_tool, config_tool
        )
        if not product_type:
            return

        apply_qualitypt = self._find_matching_quality_pt(
            product_type.name, quality_vulnerability_management["PTS"]
        )
        if not apply_qualitypt:
            return

        self._apply_quality_pt_threshold(
            input_core,
            config_tool,
            quality_vulnerability_management,
            apply_qualitypt[product_type.name],
        )

    def _find_matching_quality_pt(self, pt_name, quality_pts):
        return next(
            filter(lambda qapt: pt_name in qapt, quality_pts),
            None,
        )

    def _apply_quality_pt_threshold(
        self, input_core, config_tool, quality_vulnerability_management, pt_info
    ):
        model = config_tool["BREAK_BUILD_MANAGER"]["MODEL"]
        pt_profile = pt_info["PROFILE"] if model == "severity" else None
        pt_profile_priority = pt_info["PROFILE_PRIORITY"] if model == "priority" else None
        pt_apps = pt_info["APPS"]
        applies_to_pipeline = pt_apps == "ALL" or any(
            pd in input_core.scope_pipeline for pd in pt_apps
        )

        if pt_profile and applies_to_pipeline:
            input_core.threshold_defined.vulnerability = LevelVulnerability(
                quality_vulnerability_management[pt_profile]
            )
        if pt_profile_priority and applies_to_pipeline:
            input_core.threshold_defined.priority = LevelPriority(
                quality_vulnerability_management[pt_profile_priority]
            )

    def _handle_context_extraction(
        self,
        dict_args: dict,
        module_name: str,
        path_file_results: str,
        module_config: dict,
        tool_gateway: any = None,
        config_tool: dict = None
    ) -> None:
        # Register tool gateway if provided
        if tool_gateway:
            self.context_extraction_gateway.register_tool_gateway(module_name, tool_gateway)
        
        try:
            self.context_extraction_gateway.extract_context(
                module_name=module_name,
                path_file_results=path_file_results,
                remote_config=module_config,
                config_tool=config_tool,
                print_to_logs=dict_args.get("context") == "true"
            )
        except Exception as e:
            logger.error(f"Context extraction failed for {module_name}: {str(e)}")
            # Continue execution even if context extraction fails