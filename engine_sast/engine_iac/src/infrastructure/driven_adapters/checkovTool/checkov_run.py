import yaml
import subprocess
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)

CHECKOV_PACKAGE = "checkov"
CHECKOV_CONFIG_FILE = "checkov_config.yaml"


def create_config_file(checkov_config: CheckovConfig):
    with open(checkov_config.path_config_file + CHECKOV_CONFIG_FILE, "w") as file:
        test = yaml.dump(checkov_config.dict_confg_file)
        print(test)
        checvkov_yaml_config_file = yaml.dump(checkov_config.dict_confg_file, file)
        print(checvkov_yaml_config_file)
        file.close()


def run_checkov(checkov_config: CheckovConfig):
    result = subprocess.run(
        [
            "checkov",
            "--config-file",
            checkov_config.path_config_file + CHECKOV_CONFIG_FILE,
        ],
        capture_output=True,
        shell=True,
    )
    return result
