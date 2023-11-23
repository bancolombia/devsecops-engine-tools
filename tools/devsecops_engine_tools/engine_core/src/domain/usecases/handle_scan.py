from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.InputCore import InputCore
from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import (
    runner_engine_iac,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.send_defect_dojo import (
    send_defect_dojo,
)
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.checkov.CheckovDeserealizator import (
    CheckovDeserealizator,
)


MESSAGE_ENABLED = "not yet enabled"


@dataclass
class HandleScan:
    dict_args: dict[str, any]

    def process(self):
        if "engine_iac" in self.dict_args["tool"]:
            result_list_engine_iac = runner_engine_iac(
                self.dict_args["azure_remote_config_repo"],
                self.dict_args["azure_remote_config_path"],
                "CHECKOV",
                self.dict_args["environment"],
            )
            if self.dict_args["send_to_defectdojo"]:
                send_defect_dojo("Checkov Scan", result_list_engine_iac.results_scan_list, self.dict_args)
            rules_scaned = result_list_engine_iac.rules_scaned
            totalized_exclusions = result_list_engine_iac.exclusions_all
            if result_list_engine_iac.exclusions_scope != None:
                totalized_exclusions.update(result_list_engine_iac.exclusions_scope)
            level_compliance_defined = result_list_engine_iac.level_compliance
            scope_pipeline = result_list_engine_iac.scope_pipeline
            checkov_deserealizator = CheckovDeserealizator(
                result_list_engine_iac.results_scan_list
            )
            input_core = InputCore(
                totalized_exclusions=totalized_exclusions,
                level_compliance_defined=level_compliance_defined,
                rules_scaned=rules_scaned,
                scope_pipeline=scope_pipeline,
            )
            return checkov_deserealizator, input_core
        elif "engine_dast" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_secret" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
        elif "engine_dependencies" in self.dict_args["tool"]:
            print(MESSAGE_ENABLED)
