import pytest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import ContainerScaScan

@pytest.fixture
def mock_tool_run():
    return MagicMock()

@pytest.fixture
def mock_tool_remote():
    return MagicMock()

@pytest.fixture
def mock_tool_images():
    return MagicMock()

@pytest.fixture
def mock_tool_deseralizator():
    return MagicMock()

@pytest.fixture
def container_sca_scan(mock_tool_run, mock_tool_remote, mock_tool_images, mock_tool_deseralizator):
    return ContainerScaScan(mock_tool_run, mock_tool_remote, mock_tool_images, mock_tool_deseralizator, {}, "token")

def test_get_remote_config(container_sca_scan):
    container_sca_scan.tool_remote.get_remote_config.return_value = {"config_key": "config_value"}
    assert container_sca_scan.get_remote_config("file_path") == {"config_key": "config_value"}

def test_scan_image(container_sca_scan):
    container_sca_scan.tool_images.list_images.return_value = ["image1", "image2"]
    assert container_sca_scan.scan_image() == ["image1", "image2"]

def test_get_variable(container_sca_scan):
    container_sca_scan.tool_remote.get_variable.return_value = {"variable_key": "variable_value"}
    assert container_sca_scan.get_variable("variable") == {"variable_key": "variable_value"}

def test_process(container_sca_scan):
    container_sca_scan.tool_run.run_tool_container_sca.return_value = {"result_key": "result_value"}
    assert container_sca_scan.process() == {"result_key": "result_value"}

def test_deseralizator(container_sca_scan):
    container_sca_scan.tool_deseralizator.get_list_findings.return_value = ["finding1", "finding2"]
    assert container_sca_scan.deseralizator("image_scanned") == ["finding1", "finding2"]
