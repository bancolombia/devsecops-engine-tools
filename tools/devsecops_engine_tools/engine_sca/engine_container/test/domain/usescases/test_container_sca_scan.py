import pytest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.container_sca_scan import (
    ContainerScaScan,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import Component


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
def container_sca_scan(
    mock_tool_run,
    mock_tool_remote,
    mock_tool_images,
    mock_tool_deserializator,
):
    return ContainerScaScan(
        mock_tool_run,
        mock_tool_remote,
        mock_tool_images,
        mock_tool_deserializator,
        "1234",
        "token",
        "token_engine_container",
        "image_to_scan",
        {"exclusions": "exclusions"},
        "pipeline_name",
        "context",
    )


def test_get_image(container_sca_scan):
    container_sca_scan.tool_images.list_images.return_value = ["image1", "image2"]
    assert container_sca_scan._get_image("image_to_scan") == ["image1", "image2"]


def test_process_image_not_already_scanned(container_sca_scan):
    mock_image = MagicMock()
    mock_image.tags = ["my_image:1234"]

    container_sca_scan._get_image = MagicMock(return_value=mock_image)
    container_sca_scan._get_base_image = MagicMock(return_value="base_image:latest")
    container_sca_scan.tool_run = MagicMock()
    component_list = [
        Component("component1", "version1"),
        Component("component2", "version2"),
    ]
    container_sca_scan.tool_run.run_tool_container_sca.return_value = (
        "my_image:1234_scan_result.json",
        component_list,
    )

    image_scanned, base_image, components = container_sca_scan.process()

    assert image_scanned == "my_image:1234_scan_result.json"
    container_sca_scan._get_image.assert_called_once_with(
        container_sca_scan.image_to_scan
    )
    container_sca_scan.tool_run.run_tool_container_sca.assert_called_once_with(
        container_sca_scan.remote_config,
        container_sca_scan.secret_tool,
        container_sca_scan.token_engine_container,
        "my_image:1234",
        "my_image:1234_scan_result.json",
        "base_image:latest",
        {'exclusions': 'exclusions'},
        False,
    )


def test_deserialize(container_sca_scan):
    container_sca_scan.tool_deseralizator.get_list_findings.return_value = [
        "finding1",
        "finding2",
    ]
    assert container_sca_scan.deseralizator("image_scanned") == ["finding1", "finding2"]


def test_validate_black_list_base_image_calls_tool_images(container_sca_scan):
    base_image = "ubuntu:latest"
    black_list = ["alpine:3.12", "ubuntu:14.04"]
    container_sca_scan.tool_images.validate_black_list_base_image = MagicMock(return_value="not_blacklisted")

    result = container_sca_scan._validate_black_list_base_image(base_image, black_list)

    container_sca_scan.tool_images.validate_black_list_base_image.assert_called_once_with(base_image, black_list)
    assert result == "not_blacklisted"


def test_validate_black_list_base_image_blacklisted(container_sca_scan):
    base_image = "alpine:3.12"
    black_list = ["alpine:3.12", "ubuntu:14.04"]
    container_sca_scan.tool_images.validate_black_list_base_image = MagicMock(return_value="blacklisted")

    result = container_sca_scan._validate_black_list_base_image(base_image, black_list)

    container_sca_scan.tool_images.validate_black_list_base_image.assert_called_once_with(base_image, black_list)
    assert result == "blacklisted"