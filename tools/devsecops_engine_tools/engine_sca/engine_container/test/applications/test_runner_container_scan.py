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
    with patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.init_engine_sca_rm', return_value='result'):
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
    with patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.init_engine_sca_rm', return_value='result'):
        with pytest.raises(Exception):
            runner_engine_container(**valid_args_and_config)
