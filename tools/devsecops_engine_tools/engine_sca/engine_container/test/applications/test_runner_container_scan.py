from devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan import runner_engine_container

import pytest
from unittest.mock import patch

# Define mock classes or functions for the external dependencies
class MockTrivyScan:
    pass

class MockTrivyDeserializator:
    pass

class MockPrismaCloudManagerScan:
    pass

class MockPrismaDeserealizator:
    pass

class MockDockerImages:
    pass

class MockAzureRemoteConfig:
    pass

def test_runner_engine_container_with_prisma():
    valid_args_and_config = {
        'dict_args': [
            "--remote_config_repo",
            "NU0429001_DevSecOps_Remote_Config"
        ],
        'config_tool': {'ENGINE_CONTAINER': 'prisma'},
        'token': 'token'
    }
    with patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.PrismaCloudManagerScan', return_value=MockPrismaCloudManagerScan()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_deserialize_output.PrismaDeserealizator', return_value=MockPrismaDeserealizator()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images.DockerImages', return_value=MockDockerImages()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.azure.azure_remote_config.AzureRemoteConfig', return_value=MockAzureRemoteConfig()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.init_engine_sca_rm', return_value='result'):
        with pytest.raises(Exception):
            runner_engine_container(**valid_args_and_config)

def test_runner_engine_container_with_trivy():
    valid_args_and_config = {
        'dict_args': [
            "--remote_config_repo",
            "NU0429001_DevSecOps_Remote_Config"
        ],
        'config_tool': {'ENGINE_CONTAINER': 'trivy'},
        'token': 'token'
    }
    with patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.TrivyScan', return_value=MockTrivyScan()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_deserialize_output.TrivyDeserializator', return_value=MockTrivyDeserializator()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images.DockerImages', return_value=MockDockerImages()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.azure.azure_remote_config.AzureRemoteConfig', return_value=MockAzureRemoteConfig()), \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.init_engine_sca_rm', return_value='result'):
        with pytest.raises(Exception):
            runner_engine_container(**valid_args_and_config)
