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

    # Mock the Docker client and its images.list method
    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    mock_image = MagicMock()
    mock_image.tags = [image_to_scan]
    mock_image.id = "test_id"
    mock_image.attrs = {"Created": "2023-08-02T12:34:56.789Z"}

    mock_client.images.list.return_value = [mock_image]

    # Act
    result = docker_images.list_images(image_to_scan)

    # Assert
    assert result == mock_image
    assert result.id == "test_id"
    assert result.tags == [image_to_scan]
    assert result.attrs["Created"] == "2023-08-02T12:34:56.789Z"
    mock_docker_client.assert_called_once()
    mock_client.images.list.assert_called_once()
