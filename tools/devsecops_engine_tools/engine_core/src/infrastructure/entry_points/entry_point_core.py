import argparse

from devsecops_engine_tools.engine_sast.engine_iac.src.applications.runner_iac_scan import runner_engine_iac
from devsecops_engine_tools.engine_core.src.domain.model.Exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.InputCore import InputCore
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.checkov.Checkov_deserealizator import CheckovDeserealizator
from devsecops_engine_tools.engine_core.src.domain.usecases.break_build import BreakBuild
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.checkov_json_integrator import checks_integration 
from devsecops_engine_tools.engine_core.src.infrastructure.entry_points.send_vultracker import send_vultracker

def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
    parser.add_argument("--tool", type=str, required=True, help="")
    parser.add_argument("--environment", type=str, required=True, help="")

    args = parser.parse_args()
    return (
        args.azure_remote_config_repo,
        args.azure_remote_config_path,
        args.tool,
        args.environment,
    )

def init_engine_core():
    result_list_engine_iac = runner_engine_iac()
    #file_path = checks_integration(result_list_engine_iac.results_scan_list)
    #send_vultracker(file_path)
    rules_scaned = result_list_engine_iac.rules_scaned
    totalized_exclusions = result_list_engine_iac.exclusions_all
    if result_list_engine_iac.exclusions_scope != None: totalized_exclusions.update(result_list_engine_iac.exclusions_scope)
    level_compliance_defined = result_list_engine_iac.level_compliance
    scope_pipeline = result_list_engine_iac.scope_pipeline
    checkov_deserealizator = CheckovDeserealizator(result_list_engine_iac.results_scan_list)
    input_core = InputCore(totalized_exclusions=totalized_exclusions, level_compliance_defined=level_compliance_defined, rules_scaned=rules_scaned, scope_pipeline=scope_pipeline)
    break_build_result = BreakBuild(deserializer_gateway=checkov_deserealizator,input_core=input_core)

init_engine_core()