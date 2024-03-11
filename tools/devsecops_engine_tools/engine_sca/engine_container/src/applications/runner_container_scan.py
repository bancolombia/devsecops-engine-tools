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


from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import (
    TrivyScan,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_deserialize_output import (
    TrivyDeserializator,
)


def runner_engine_container(dict_args, config_tool, token,tool_remote):
    try:
        if config_tool["ENGINE_CONTAINER"]["TOOL"].lower() == "trivy":
            tool_run = TrivyScan()
            tool_deseralizator = TrivyDeserializator()
        elif config_tool["ENGINE_CONTAINER"]["TOOL"].lower() == "prisma":
            tool_run = PrismaCloudManagerScan()
            tool_deseralizator = PrismaDeserealizator()
        tool_images = DockerImages()
        return init_engine_sca_rm(
            tool_run,
            tool_remote,
            tool_images,
            tool_deseralizator,
            dict_args,
            token,
            config_tool,
        )

    except Exception as e:
        raise Exception(f"Error SCAN engine container : {str(e)}")


if __name__ == "__main__":
    runner_engine_container()
