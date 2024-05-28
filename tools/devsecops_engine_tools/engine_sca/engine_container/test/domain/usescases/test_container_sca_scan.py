import pytest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import (
    ContainerScaScan,
)


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
def mock_tool_deserializator():
    return MagicMock()


@pytest.fixture
def mock_tool_build_id():
    return MagicMock()


@pytest.fixture
def container_sca_scan(
    mock_tool_run,
    mock_tool_remote,
    mock_tool_images,
    mock_tool_deserializator,
    mock_tool_build_id,
):
    dict_args = {"remote_config_repo": "path_to_config"}
    return ContainerScaScan(
        mock_tool_run,
        mock_tool_remote,
        mock_tool_images,
        mock_tool_deserializator,
        mock_tool_build_id,
        "token",
    )


def test_scan_image(container_sca_scan):
    container_sca_scan.tool_images.list_images.return_value = ["image1", "image2"]
    assert container_sca_scan.scan_image() == ["image1", "image2"]


def test_process(container_sca_scan):
    container_sca_scan.tool_run.run_tool_container_sca.return_value = {
        "result_key": "result_value"
    }
    assert container_sca_scan.process() == {"result_key": "result_value"}


def test_deserialize(container_sca_scan):
    container_sca_scan.tool_deseralizator.get_list_findings.return_value = [
        "finding1",
        "finding2",
    ]
    assert container_sca_scan.deseralizator("image_scanned") == ["finding1", "finding2"]
