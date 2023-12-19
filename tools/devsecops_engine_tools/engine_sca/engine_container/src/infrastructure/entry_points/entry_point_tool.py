import os
import configparser
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import PrismaCloudManagerScan
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import ContainerScaScan

from devsecops_engine_utilities.utils.printers import (
    Printers,
)

ENGINESAST_ENGINEIAC = "enginesast.engineiac"


def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_remote_config_repo = config.get(
        ENGINESAST_ENGINEIAC, "azure_remote_config_repo", fallback=None
    )
    azure_remote_config_path = config.get(
        ENGINESAST_ENGINEIAC, "azure_remote_config_path", fallback=None
    )
    tool = config.get(ENGINESAST_ENGINEIAC, "tool", fallback=None)
    environment = config.get(ENGINESAST_ENGINEIAC, "environment", fallback=None)
    return (
        azure_remote_config_repo,
        azure_remote_config_path,
        tool,
        environment,
    )


def init_engine_sca_rm( tool_run,tool_images,tool_deseralizator,dict_args, token):

    Printers.print_logo_tool()
   
    container_sca_scan = ContainerScaScan(tool_run,tool_images,tool_deseralizator,dict_args, token)
    print(container_sca_scan.scanImage())
    return container_sca_scan.deseralizator()
    



