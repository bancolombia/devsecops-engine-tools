import unittest
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.helpers.utils import set_repository

class TestSonarUtils(unittest.TestCase):

    def test_set_repository_mr(self):
        # Arrange
        pipeline_name = "some_pipeline"
        source_code_management = "https://example.com/repo"

        # Act
        result = set_repository(pipeline_name, source_code_management)

        # Assert
        self.assertEqual(result, source_code_management)

    def test_set_repository_not_mr(self):
        # Arrange
        pipeline_name = "some_pipeline_MR_123"
        source_code_management = "https://example.com/repo"

        # Act
        result = set_repository(pipeline_name, source_code_management)

        # Assert
        self.assertEqual(result, "https://example.com/repo?path=/123")