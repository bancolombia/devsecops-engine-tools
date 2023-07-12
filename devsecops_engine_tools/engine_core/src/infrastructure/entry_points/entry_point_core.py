import argparse

from engine_sast.engine_iac.src.applications.runner_iac_scan import runner_engine_iac
from engine_core.src.domain.model.Vulnerability import Vulnerability
from engine_core.src.domain.model.Level_Compliance import LevelCompliance
from engine_core.src.domain.model.Exclusions import Exclusions
from engine_core.src.infrastructure.driven_adapters.checkov.Checkov_deserealizator import CheckovDeserealizator

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

# def init_engine_core(remote_config_repo, remote_config_path, tool):

# IMPORTANTEEEE: En los entry points se conecta los driven adapter, con los casos de uso
def init_engine_core():
    result_list_engine_iac = runner_engine_iac() # lista con exclusion All de tool en este caso checkov, lista con exclusion pipeline de tool, compliance de tool), result_json list (según la cantidad de escaneos) , rules_scan (todas k8s y docker)
    total_list_vulnerability = []
    for result in result_list_engine_iac:
        total_list_vulnerability.append(CheckovDeserealizator.get_list_vulnerability(results_list=result.result_json))
    #va dentro de un for, donde voy cargando todo lo que saco de lo que me pasa Cesarillo
    #    exclusion_for_pipeline = Exclusions()
    #    vulnerability_exclusions_pipeline[] = Vulnerability() 
    #acaba for
    level_compliance_defined = LevelCompliance() #Le paso los datos que obtenga de lo que manda Cesarillo

    
    # break_build(list_vulnerabilities,umbrales)
    print("init_engine_core")

init_engine_core()