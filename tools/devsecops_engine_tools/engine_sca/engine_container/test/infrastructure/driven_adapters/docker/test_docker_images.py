from unittest.mock import patch
import pytest
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images import DockerImages


        
class TestDockerImages:
    @pytest.fixture
    def docker_images(self):
        with patch('docker.from_env') as mock_from_env:
            mock_client = MagicMock()
            mock_from_env.return_value = mock_client
            yield DockerImages()

    def test_list_images(self, docker_images):
        mock_images_list = [
            MagicMock(id='image_id_1', tags=['tag1'], attrs={'Created': '2024-01-01T00:00:00Z'}),
            MagicMock(id='image_id_2', tags=['tag2'], attrs={'Created': '2024-02-02T00:00:00Z'}),
            MagicMock(id='image_id_3', tags=['tag3'], attrs={'Created': '2024-03-03T00:00:00Z'}),
        ]

        with patch('docker.from_env') as mock_from_env:
            mock_client = MagicMock()
            mock_from_env.return_value = mock_client
            docker_images.client = mock_client

            mock_client.images.list.return_value = mock_images_list

            latest_image = docker_images.list_images()

            mock_client.images.list.assert_called_once()
            assert latest_image.id == 'image_id_3'
            assert latest_image.tags == ['tag3']
            assert latest_image.attrs['Created'] == '2024-03-03T00:00:00Z'