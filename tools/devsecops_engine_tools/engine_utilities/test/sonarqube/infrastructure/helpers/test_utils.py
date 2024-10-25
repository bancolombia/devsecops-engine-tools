import unittest
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.helpers.utils import set_repository, set_environment

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

    def test_set_environment_production(self):
        # Arrange
        branchT = "trunk"
        branchM = "master"
        # Act
        resultT = set_environment(branchT)
        resultM = set_environment(branchM)
        #Assert
        self.assertEqual(resultT, "Production")
        self.assertEqual(resultM, "Production")

    def test_set_environment_development(self):
        # Arrange
        branch = "feature/some-feature"

        # Act
        result = set_environment(branch)

        # Assert
        self.assertEqual(result, "Development")
