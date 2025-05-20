from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_risk.src.applications.runner_engine_risk import (
    runner_engine_risk,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionGettingFindings,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
import re

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class HandleRisk:
    def __init__(
        self,
        vulnerability_management: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        print_table_gateway: PrinterTableGateway,
    ):
        self.vulnerability_management = vulnerability_management
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.print_table_gateway = print_table_gateway

    def _get_all_from_vm(self, dict_args, secret_tool, remote_config, service):
        try:
            return self.vulnerability_management.get_all(
                service,
                dict_args,
                secret_tool,
                remote_config,
            )
        except ExceptionGettingFindings as e:
            logger.error(
                "Error getting finding list in handle risk: {0}".format(str(e))
            )

    def _filter_engagements(self, engagements, service, initial_services, risk_config):
        filtered_engagements = []
        min_word_length = risk_config["HANDLE_SERVICE_NAME"]["MIN_WORD_LENGTH"]
        words = [
            word
            for word in re.split(
                risk_config["HANDLE_SERVICE_NAME"]["REGEX_GET_WORDS"], service
            )
            if len(word) > min_word_length
        ]
        check_words_regex = risk_config["HANDLE_SERVICE_NAME"]["REGEX_CHECK_WORDS"]
        min_word_amount = risk_config["HANDLE_SERVICE_NAME"]["MIN_WORD_AMOUNT"]
        endings = risk_config["HANDLE_SERVICE_NAME"]["CHECK_ENDING"]

        initial_services_lower = [service.lower() for service in initial_services]

        for engagement in engagements:
            if engagement.name.lower() in initial_services_lower:
                filtered_engagements += [engagement]
            elif re.search(check_words_regex, engagement.name.lower()) and (
                sum(1 for word in words if word.lower() in engagement.name.lower())
                >= min_word_amount
            ):
                filtered_engagements += [engagement]
            elif endings:
                if any(
                    (service.lower() + ending.lower() == engagement.name.lower())
                    for ending in endings
                ):
                    filtered_engagements += [engagement]

        return filtered_engagements

    def _exclude_services(self, dict_args, pipeline_name, service_list):
        risk_exclusions = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_risk/Exclusions.json", dict_args["remote_config_branch"]
        )
        if (
            pipeline_name in risk_exclusions
            and risk_exclusions[pipeline_name].get("SKIP_SERVICE", 0)
            and risk_exclusions[pipeline_name]["SKIP_SERVICE"].get("services", 0)
        ):
            services_to_exclude = set(
                risk_exclusions[pipeline_name]["SKIP_SERVICE"].get("services", [])
            )

            remaining_engagements = [
                engagement
                for engagement in service_list
                if engagement.name.lower()
                not in [service.lower() for service in services_to_exclude]
            ]
            excluded_engagements = [
                engagement
                for engagement in service_list
                if engagement.name.lower()
                in [service.lower() for service in services_to_exclude]
            ]

            print(
                f"Services to exclude: {[engagement.name for engagement in excluded_engagements]}"
            )
            logger.info(
                f"Services to exclude: {[engagement.name for engagement in excluded_engagements]}"
            )

            return remaining_engagements
        return service_list

    def _should_skip_analysis(self, remote_config, pipeline_name, exclusions):
        ignore_pattern = remote_config["IGNORE_ANALYSIS_PATTERN"]
        return re.match(ignore_pattern, pipeline_name, re.IGNORECASE) or (
            pipeline_name in exclusions
            and exclusions[pipeline_name].get("SKIP_TOOL", 0)
        )

    def process(self, dict_args: any, remote_config: any):
        risk_config = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_risk/ConfigTool.json", dict_args["remote_config_branch"]
        )
        risk_exclusions = self.remote_config_source_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_risk/Exclusions.json", dict_args["remote_config_branch"]
        )
        pipeline_name = self.devops_platform_gateway.get_variable("pipeline_name")

        input_core = InputCore(
            [],
            {},
            "",
            "",
            pipeline_name,
            pipeline_name,
            self.devops_platform_gateway.get_variable("stage").capitalize(),
        )

        if self._should_skip_analysis(risk_config, pipeline_name, risk_exclusions):
            print("Tool skipped by DevSecOps Policy.")
            dict_args["send_metrics"] = "false"
            return [], input_core

        secret_tool = None
        if dict_args["use_secrets_manager"] == "true":
            secret_tool = self.secrets_manager_gateway.get_secret(remote_config)

        service = pipeline_name
        service_list = []
        initial_services = []
        initial_services += [service]

        match_parent = re.match(
            risk_config["PARENT_ANALYSIS"]["REGEX_GET_PARENT"], service
        )
        if risk_config["PARENT_ANALYSIS"]["ENABLED"].lower() == "true" and match_parent:
            parent_service = match_parent.group(0)
            initial_services += [parent_service]

        if risk_config["HANDLE_SERVICE_NAME"]["ENABLED"].lower() == "true":
            service = next(
                (
                    pipeline_name.replace(ending, "")
                    for ending in risk_config["HANDLE_SERVICE_NAME"]["CHECK_ENDING"]
                    if pipeline_name.endswith(ending)
                ),
                pipeline_name,
            )
            initial_services += [service]
            match_service_code = re.match(
                risk_config["HANDLE_SERVICE_NAME"]["REGEX_GET_SERVICE_CODE"], service
            )
            if match_service_code:
                service_code = match_service_code.group(0)
                initial_services += [
                    service.format(service_code=service_code)
                    for service in risk_config["HANDLE_SERVICE_NAME"]["ADD_SERVICES"]
                ]
                engagements = self.vulnerability_management.get_active_engagements(
                    service_code, dict_args, secret_tool, remote_config
                )
                service_list += self._filter_engagements(
                    engagements, service, initial_services, risk_config
                )
        else:
            for service in initial_services:
                engagements = self.vulnerability_management.get_active_engagements(
                    service, dict_args, secret_tool, remote_config
                )
                for engagement in engagements:
                    if engagement.name.lower() == service.lower():
                        service_list += [engagement]
                        break

        new_service_list = self._exclude_services(
            dict_args, pipeline_name, service_list
        )

        for engagement in new_service_list:
            print(f"Service to analyze: {engagement.name}, URL: {engagement.vm_url}")
            logger.info(
                f"Service to analyze: {engagement.name}, URL: {engagement.vm_url}"
            )

        findings = []
        exclusions = []
        for service in new_service_list:
            findings_list, exclusions_list = self._get_all_from_vm(
                dict_args, secret_tool, remote_config, service.name
            )
            findings += findings_list
            exclusions += exclusions_list

        result = runner_engine_risk(
            dict_args,
            findings,
            exclusions,
            [service.name for service in new_service_list],
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
            self.print_table_gateway,
        )

        return result, input_core
