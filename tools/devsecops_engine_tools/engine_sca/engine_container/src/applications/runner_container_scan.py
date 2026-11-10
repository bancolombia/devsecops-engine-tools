from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sca_rm,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import (
    PrismaCloudManagerScan,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images import (
    DockerImages,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_deserialize_output import (
    PrismaDeserealizator,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan import (
    CortexCloudManagerScan,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_deserialize_output import (
    CortexDeserealizator,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import (
    TrivyScan,
)
from devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_deserialize_output import (
    TrivyDeserializator,
)


def runner_engine_container(dict_args, tool, secret_tool, tool_remote, remote_config_source_gateway):
    try:
        if tool.lower() == "trivy":
            tool_run = TrivyScan()
            tool_deseralizator = TrivyDeserializator()
        elif tool.lower() == "prisma":
            tool_run = PrismaCloudManagerScan()
            tool_deseralizator = PrismaDeserealizator()
        elif tool.lower() == "cortex":
            tool_run = CortexCloudManagerScan()
            tool_deseralizator = CortexDeserealizator()
        tool_images = DockerImages()
        
        findings_list, input_core, sbom_components = init_engine_sca_rm(
            tool_run,
            tool_remote,
            remote_config_source_gateway,
            tool_images,
            tool_deseralizator,
            dict_args,
            secret_tool,
            tool,
        )
        
        return findings_list, input_core, sbom_components, tool_run

    except Exception as e:
        raise Exception(f"Error SCAN engine container : {str(e)}")


if __name__ == "__main__":
    runner_engine_container()
