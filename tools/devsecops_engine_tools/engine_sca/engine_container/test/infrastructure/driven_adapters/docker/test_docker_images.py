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

    # Mock the Docker client and su método images.list
    mock_client = MagicMock()
    mock_docker_client.return_value = mock_client

    # Crea varias imágenes mock con múltiples tags
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

    # Añade las imágenes mock al retorno de images.list
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
