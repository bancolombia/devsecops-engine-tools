from datetime import datetime
import pytest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images import (
    DockerImages,
)


@pytest.fixture
def mock_docker_client():
    with patch("docker.from_env") as mock:
        yield mock

def test_list_images(mock_docker_client):
    # Arrange
    docker_images = DockerImages()
    image_to_scan = "test_image:latest"

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_image1 = MagicMock()
    mock_image1.tags = ["non_matching_image:latest", "other_tag:v1"]
    mock_image1.id = "non_matching_id_1"
    mock_image1.attrs = {"Created": "2023-08-01T10:00:00.000Z"}

    mock_image2 = MagicMock()
    mock_image2.tags = ["another_non_matching_image:latest", "different_tag:v2"]
    mock_image2.id = "non_matching_id_2"
    mock_image2.attrs = {"Created": "2023-08-01T11:00:00.000Z"}

    mock_image3 = MagicMock()
    mock_image3.tags = ["some_other_image:v1", image_to_scan, "another_tag:v2"]
    mock_image3.id = "test_id"
    mock_image3.attrs = {"Created": "2023-08-02T12:34:56.789Z"}

    mock_client.images.list.return_value = [mock_image1, mock_image2, mock_image3]

    # Act
    result = docker_images.list_images(image_to_scan)

    # Assert
    assert result == mock_image3
    assert result.id == "test_id"
    assert image_to_scan in result.tags
    assert result.attrs["Created"] == "2023-08-02T12:34:56.789Z"
    mock_docker_client.assert_called_once()
    mock_client.images.list.assert_called_once()


def test_list_images_no_matching_image(mock_docker_client):
   
    docker_images = DockerImages()
    image_to_scan = "non_existent_image:latest"

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_image1 = MagicMock()
    mock_image1.tags = ["some_image:latest"]
    mock_image2 = MagicMock()
    mock_image2.tags = ["another_image:latest"]

    mock_client.images.list.return_value = [mock_image1, mock_image2]


    result = docker_images.list_images(image_to_scan)


    assert result is None
    mock_client.images.list.assert_called_once()


def test_list_images_exception(mock_docker_client):

    docker_images = DockerImages()
    image_to_scan = "test_image:latest"

    mock_client = MagicMock()
    mock_docker_client.side_effect = Exception("Docker not running")


    result = docker_images.list_images(image_to_scan)


    assert result is None
    mock_docker_client.assert_called_once()


def test_get_base_image_parent_image(mock_docker_client):

    docker_images = DockerImages()

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    matching_image = MagicMock()
    matching_image.id = "image_id"

    parent_image_details = {"RepoTags": ["base_image:latest"]}
    mock_client.api.inspect_image.side_effect = [
        {"Parent": "parent_id"},
        parent_image_details,
    ]


    result = docker_images.get_base_image(matching_image)


    assert result == None


def test_get_base_image_source_label(mock_docker_client):

    docker_images = DockerImages()

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    matching_image = MagicMock()
    matching_image.id = "image_id"

    mock_client.api.inspect_image.return_value = {
        "Config": {"Labels": {"x86.image.name": "source_image:1.0"}},
    }

    result = docker_images.get_base_image(matching_image)

    assert result == "source_image:1.0"
    mock_client.api.inspect_image.assert_called_once_with("image_id")


def test_get_base_image_no_base_image(mock_docker_client):

    docker_images = DockerImages()

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    matching_image = MagicMock()
    matching_image.id = "image_id"

    mock_client.api.inspect_image.return_value = {"Config": {"Labels": {}}}

 
    result = docker_images.get_base_image(matching_image)

   
    assert result is None
    mock_client.api.inspect_image.assert_called_once_with("image_id")


def test_get_base_image_exception(mock_docker_client):

    docker_images = DockerImages()

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    matching_image = MagicMock()
    matching_image.id = "image_id"

    mock_client.api.inspect_image.side_effect = Exception("Inspection failed")

    result = docker_images.get_base_image(matching_image)

    assert result is None
    mock_client.api.inspect_image.assert_called_once_with("image_id")

def test_validate_base_image_date_with_baseline_date(mock_docker_client):
    docker_images = DockerImages()
    matching_image = MagicMock()
    matching_image.id = "image_id"
    referenced_date = "20230801"

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_client.api.inspect_image.return_value = {
        "Config": {"Labels": {"x86.baseline.date": "20230802"}}
    }

    result = docker_images.validate_base_image_date(matching_image, referenced_date)

    assert result is True
    mock_client.api.inspect_image.assert_called_once_with("image_id")


def test_validate_base_image_date_with_base_image_label(mock_docker_client):
    docker_images = DockerImages()
    matching_image = MagicMock()
    matching_image.id = "image_id"
    referenced_date = "20230801"

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_client.api.inspect_image.return_value = {
        "Config": {"Labels": {"image.base.ref.name": "base_image_20230802"}}
    }

    result = docker_images.validate_base_image_date(matching_image, referenced_date)

    assert result is True
    mock_client.api.inspect_image.assert_called_once_with("image_id")


def test_validate_base_image_date_with_invalid_date(mock_docker_client):
    docker_images = DockerImages()
    matching_image = MagicMock()
    matching_image.id = "image_id"
    referenced_date = "20230801"

    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_client.api.inspect_image.return_value = {
        "Config": {"Labels": {"image.base.ref.name": "base_image_invalid_date"}}
    }

    result = docker_images.validate_base_image_date(matching_image, referenced_date)

    assert result is False
    mock_client.api.inspect_image.assert_called_once_with("image_id")


def test_validate_base_image_date_with_exception(mock_docker_client):
    docker_images = DockerImages()
    matching_image = MagicMock()
    matching_image.id = "image_id"
    referenced_date = "20230801"

    mock_client = MagicMock()
    mock_docker_client.side_effect = Exception("Inspection failed")

    result = docker_images.validate_base_image_date(matching_image, referenced_date)

    assert result is False
    mock_docker_client.assert_called_once()


def test_get_base_image_from_labels():
    docker_images = DockerImages()
    labels = {
        "image.base.ref.name": "base_image",
        "source_images": "source_image",
        "source-image": "source_image_alt",
    }

    result = docker_images.get_base_image_from_labels(labels)

    assert result == "base_image"


def test_extract_date_from_image():
    docker_images = DockerImages()
    image_name = "base_image_20230802"

    result = docker_images.extract_date_from_image(image_name)

    assert result == datetime.strptime("20230802", "%Y%m%d")


def test_extract_date_from_image_invalid_format():
    docker_images = DockerImages()
    image_name = "base_image_invalid_date"

    result = docker_images.extract_date_from_image(image_name)

    assert result is None


def test_validate_date():
    docker_images = DockerImages()
    date = datetime.strptime("20230802", "%Y%m%d")
    referenced_date = "20230801"

    result = docker_images.validate_date(date, referenced_date)

    assert result is True


def test_validate_date_with_older_date():
    docker_images = DockerImages()
    date = datetime.strptime("20230801", "%Y%m%d")
    referenced_date = "20230802"

    result = docker_images.validate_date(date, referenced_date)

    assert result is False
