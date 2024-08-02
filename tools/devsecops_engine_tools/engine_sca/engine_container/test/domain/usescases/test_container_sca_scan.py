import pytest
from unittest.mock import MagicMock, patch
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
        "image_to_scan"
    )


def test_get_image(container_sca_scan):
    container_sca_scan.tool_images.list_images.return_value = ["image1", "image2"]
    assert container_sca_scan.get_image("image_to_scan") == ["image1", "image2"]


def test_get_images_already_scanned(container_sca_scan):
    with patch("os.path.join") as mock_path_join, patch(
        "os.getcwd"
    ) as mock_getcwd, patch("os.path.exists") as mock_path_exists, patch(
        "builtins.open"
    ) as mock_open:
        mock_path_join.return_value = "/path/to/scanned_images.txt"
        mock_path_exists.return_value = False
        mock_open.return_value = MagicMock()
        container_sca_scan.get_images_already_scanned()
        assert mock_open.call_count == 2


def test_set_image_scanned(container_sca_scan):
    with patch("builtins.open") as mock_open:
        container_sca_scan.set_image_scanned("result.json")
        assert mock_open.call_count == 1


def test_process_image_already_scanned(container_sca_scan):
    mock_image = MagicMock()
    mock_image.tags = ["my_image:1234"]
    container_sca_scan.get_images_already_scanned = MagicMock()
    container_sca_scan.get_image = MagicMock()
    container_sca_scan.get_image.return_value = mock_image
    container_sca_scan.get_images_already_scanned.return_value = [
        "my_image:1234_scan_result.json"
    ]
    assert container_sca_scan.process() == None


def test_process_image_not_already_scanned(container_sca_scan):
    mock_image = MagicMock()
    mock_image.tags = ["my_image:1234"]
    container_sca_scan.get_images_already_scanned = MagicMock()
    container_sca_scan.get_image = MagicMock()
    container_sca_scan.get_image.return_value = mock_image
    container_sca_scan.get_images_already_scanned.return_value = [
        "my_image_scan_result.json"
    ]
    container_sca_scan.tool_run.run_tool_container_sca.return_value = [
        "my_image:1234_scan_result.json"
    ]
    container_sca_scan.set_image_scanned = MagicMock()
    assert container_sca_scan.process() == ["my_image:1234_scan_result.json"]



def test_deserialize(container_sca_scan):
    container_sca_scan.tool_deseralizator.get_list_findings.return_value = [
        "finding1",
        "finding2",
    ]
    assert container_sca_scan.deseralizator("image_scanned") == ["finding1", "finding2"]
