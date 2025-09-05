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
        "docker_address",
        "context",
    )


def test_get_image(container_sca_scan):
    container_sca_scan.tool_images.list_images.return_value = ["image1", "image2"]
    assert container_sca_scan._get_image("image_to_scan") == ["image1", "image2"]


def test_get_images_already_scanned(container_sca_scan):
    with patch("os.path.join") as mock_path_join, patch(
        "os.getcwd"
    ) as mock_getcwd, patch("os.path.exists") as mock_path_exists, patch(
        "builtins.open"
    ) as mock_open:
        mock_path_join.return_value = "/path/to/scanned_images.txt"
        mock_path_exists.return_value = False
        container_sca_scan._get_images_already_scanned()
        assert mock_open.call_count == 2


def test_set_image_scanned(container_sca_scan):
    with patch("builtins.open") as mock_open:
        container_sca_scan._set_image_scanned("result.json")
        assert mock_open.call_count == 1


def test_process_image_already_scanned(container_sca_scan):
    mock_image = MagicMock()
    mock_image.tags = ["my_image:1234"]
    container_sca_scan._get_image = MagicMock(return_value=mock_image)
    container_sca_scan._get_base_image = MagicMock(return_value="base_image:latest")
    container_sca_scan._get_images_already_scanned = MagicMock(
        return_value=["my_image:1234"]
    )
    container_sca_scan.tool_run = MagicMock()
    container_sca_scan._set_image_scanned = MagicMock()

    image_scanned, base_image, components = container_sca_scan.process()

    assert image_scanned is None
    assert base_image == "base_image:latest"
    container_sca_scan._get_image.assert_called_once_with(
        container_sca_scan.image_to_scan
    )
    container_sca_scan._get_images_already_scanned.assert_called_once()
    container_sca_scan.tool_run.run_tool_container_sca.assert_not_called()
    container_sca_scan._set_image_scanned.assert_not_called()


def test_process_image_not_already_scanned(container_sca_scan):
    mock_image = MagicMock()
    mock_image.tags = ["my_image:1234"]

    container_sca_scan._get_image = MagicMock(return_value=mock_image)
    container_sca_scan._get_base_image = MagicMock(return_value="base_image:latest")
    container_sca_scan._get_images_already_scanned = MagicMock(return_value=[])
    container_sca_scan.tool_run = MagicMock()
    component_list = [
        Component("component1", "version1"),
        Component("component2", "version2"),
    ]
    container_sca_scan.tool_run.run_tool_container_sca.return_value = (
        "my_image:1234_scan_result.json",
        component_list,
    )
    container_sca_scan._set_image_scanned = MagicMock()

    image_scanned, base_image, components = container_sca_scan.process()

    assert image_scanned == "my_image:1234_scan_result.json"
    container_sca_scan._get_image.assert_called_once_with(
        container_sca_scan.image_to_scan
    )
    container_sca_scan._get_images_already_scanned.assert_called_once()
    container_sca_scan.tool_run.run_tool_container_sca.assert_called_once_with(
        container_sca_scan.remote_config,
        container_sca_scan.secret_tool,
        container_sca_scan.token_engine_container,
        "my_image:1234",
        "my_image:1234_scan_result.json",
        "base_image:latest",
        {'exclusions': 'exclusions'},
        False,
        container_sca_scan.docker_address,
        False,
    )
    container_sca_scan._set_image_scanned.assert_called_once_with("my_image:1234")


def test_deserialize(container_sca_scan):
    container_sca_scan.tool_deseralizator.get_list_findings.return_value = [
        "finding1",
        "finding2",
    ]
    assert container_sca_scan.deseralizator("image_scanned") == ["finding1", "finding2"]


def test_validate_black_list_base_image_calls_tool_images(container_sca_scan):
    base_image = (["ubuntu:latest"], False)
    black_list = ["alpine:3.12", "ubuntu:14.04"]
    container_sca_scan.tool_images.validate_black_list_base_image = MagicMock()

    container_sca_scan._validate_black_list_base_image(base_image, black_list)

    container_sca_scan.tool_images.validate_black_list_base_image.assert_called_once_with(
        "ubuntu:latest", black_list  
    )


def test_validate_black_list_base_image_blacklisted(container_sca_scan):
    base_image = (["alpine:3.12"], False)
    black_list = ["alpine:3.12", "ubuntu:14.04"]
    container_sca_scan.tool_images.validate_black_list_base_image = MagicMock(
        side_effect=ValueError("blacklisted")
    )

    with pytest.raises(ValueError, match="blacklisted"):
        container_sca_scan._validate_black_list_base_image(base_image, black_list)

    container_sca_scan.tool_images.validate_black_list_base_image.assert_called_once_with(
        "alpine:3.12", black_list  
    )


def test_validate_black_list_base_image_no_base_image(container_sca_scan):
    base_image = ([], False)
    black_list = ["alpine:3.12", "ubuntu:14.04"]
    container_sca_scan.tool_images.validate_black_list_base_image = MagicMock()

    result = container_sca_scan._validate_black_list_base_image(base_image, black_list)

    container_sca_scan.tool_images.validate_black_list_base_image.assert_not_called()
    assert result is True


def test_is_compressed_file_tar(container_sca_scan):
    """Test detection of .tar files"""
    assert container_sca_scan._is_compressed_file("/path/to/image.tar") is True


def test_is_compressed_file_tar_gz(container_sca_scan):
    """Test detection of .tar.gz files"""
    assert container_sca_scan._is_compressed_file("/path/to/image.tar.gz") is True


def test_is_compressed_file_tgz(container_sca_scan):
    """Test detection of .tgz files"""
    assert container_sca_scan._is_compressed_file("/path/to/image.tgz") is True


def test_is_compressed_file_tar_bz2(container_sca_scan):
    """Test detection of .tar.bz2 files"""
    assert container_sca_scan._is_compressed_file("/path/to/image.tar.bz2") is True


def test_is_compressed_file_tar_xz(container_sca_scan):
    """Test detection of .tar.xz files"""
    assert container_sca_scan._is_compressed_file("/path/to/image.tar.xz") is True


def test_is_compressed_file_not_compressed(container_sca_scan):
    """Test that regular image names are not detected as compressed files"""
    assert container_sca_scan._is_compressed_file("nginx:latest") is False


def test_is_compressed_file_non_existent(container_sca_scan):
    """Test that paths with compressed extensions are detected even if they don't exist"""
    assert container_sca_scan._is_compressed_file("/non/existent/path.tar") is True


@patch('os.path.exists')
def test_process_compressed_file_success(mock_exists, container_sca_scan):
    """Test processing of compressed file"""
    mock_exists.return_value = True
    container_sca_scan.image_to_scan = "/path/to/image.tar.gz"
    container_sca_scan.tool_run = MagicMock()
    container_sca_scan._get_images_already_scanned = MagicMock(return_value=[])
    component_list = [Component("component1", "version1")]
    container_sca_scan.tool_run.run_tool_container_sca.return_value = (
        "result.json", 
        component_list
    )
    
    image_scanned, base_image, components = container_sca_scan.process()
    
    assert image_scanned == "result.json"
    assert base_image is None
    container_sca_scan.tool_run.run_tool_container_sca.assert_called_once_with(
        container_sca_scan.remote_config,
        container_sca_scan.secret_tool,
        container_sca_scan.token_engine_container,
        "/path/to/image.tar.gz",
        "_path_to_image_tar_gz_scan_result.json",
        None,
        container_sca_scan.exclusions,
        False,
        container_sca_scan.docker_address,
        True,  # is_compressed_file=True
    )


@patch('os.path.exists')
def test_process_compressed_file_not_found(mock_exists, container_sca_scan):
    """Test processing when compressed file doesn't exist"""
    mock_exists.return_value = False
    container_sca_scan.image_to_scan = "/path/to/nonexistent.tar.gz"
    container_sca_scan.tool_run = MagicMock()
    
    image_scanned, base_image, components = container_sca_scan.process()
    
    assert image_scanned is None
    assert base_image is None
    assert components is None
    # Verify that run_tool_container_sca was not called
    container_sca_scan.tool_run.run_tool_container_sca.assert_not_called()