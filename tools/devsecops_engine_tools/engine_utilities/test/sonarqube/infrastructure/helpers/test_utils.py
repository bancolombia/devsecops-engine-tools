import unittest
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.helpers.utils import set_repository, set_environment, invalid_branch, invalid_pipeline

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

    def test_invalid_branch_valid(self):
        # Arrange
        valid_branches = ["trunk", "master", "develop"]

        # Act & Assert
        for branch in valid_branches:
            self.assertFalse(invalid_branch(branch))

    def test_invalid_branch_invalid(self):
        # Arrange
        invalid_branches = ["feature/some-feature", "hotfix/bugfix"]

        # Act & Assert
        for branch in invalid_branches:
            self.assertTrue(invalid_branch(branch))

    def test_invalid_pipeline_valid(self):
        # Arrange
        valid_pipelines = ["some_pipeline", "feature_branch", "ProductionPipeline"]

        # Act & Assert
        for pipeline in valid_pipelines:
            self.assertFalse(invalid_pipeline(pipeline))

    def test_invalid_pipeline_invalid(self):
        # Arrange
        invalid_pipelines = ["_test", "Deprecated_pipeline", "Borrar_pipeline", "No_usar_pipeline"]
        
        # Act & Assert
        for pipeline in invalid_pipelines:
            self.assertTrue(invalid_pipeline(pipeline))
