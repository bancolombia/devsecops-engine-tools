import subprocess
from unittest.mock import patch

import pytest
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images import DockerImages
@pytest.fixture
def mock_subprocess_run_success(monkeypatch):
    def mock_run(*args, **kwargs):
        class CompletedProcess:
            def __init__(self, stdout, stderr, returncode):
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        stdout = '{"Containers":"N/A","CreatedAt":"2024-01-17 16:33:26 -0500 -05","CreatedSince":"6 weeks ago","Digest":"\\u003cnone\\u003e","ID":"3e594e5ad3ab","Repository":"engine-dev-ecr","SharedSize":"N/A","Size":"7.34MB","Tag":"db-trunk-trunk.20240126.1","UniqueSize":"N/A","VirtualSize":"7.335MB"}\n{"Containers":"N/A","CreatedAt":"2024-01-17 16:33:26 -0500 -05","CreatedSince":"6 weeks ago","Digest":"\\u003cnone\\u003e","ID":"3e594e5ad3ab","Repository":"cops-engine-dev-ecr","SharedSize":"N/A","Size":"7.34MB","Tag":"20240126.2","UniqueSize":"N/A","VirtualSize":"7.335MB"}\n'
        return CompletedProcess(stdout, b'', 0)

    monkeypatch.setattr(subprocess, 'run', mock_run)


class TestDockerImages:
    def test_list_images_success(self, mock_subprocess_run_success):
        docker_images = DockerImages()
        images = docker_images.list_images()
        assert images == [{'Containers': 'N/A', 'CreatedAt': '2024-01-17 16:33:26 -0500 -05', 'CreatedSince': '6 weeks ago', 'Digest': '<none>', 'ID': '3e594e5ad3ab', 'Repository': 'engine-dev-ecr', 'SharedSize': 'N/A', 'Size': '7.34MB', 'Tag': 'db-trunk-trunk.20240126.1', 'UniqueSize': 'N/A', 'VirtualSize': '7.335MB'}]
