import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.git_cli.git_run import GitRun

class TestGitRun(unittest.TestCase):
    @patch('os.makedirs')
    @patch('os.chdir')
    @patch('git.Repo')
    @patch('subprocess.run')
    def test_get_files_pull_request_Exception(self, mock_subprocess_run, mock_git_repo, mock_os_chdir, mock_os_makedirs):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"

        mock_git_repo.side_effect = Exception("Simulated exception")
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name)
        
        self.assertEqual(files, [])
        
    @patch('os.makedirs')
    @patch('os.chdir')
    @patch('git.Repo')
    @patch('subprocess.run')
    def test_get_files_pull_request(self, mock_subprocess_run, mock_git_repo, mock_os_chdir, mock_os_makedirs):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"

        mock_repo = MagicMock()
        mock_repo.git.diff.return_value = "file1.py\nfile2.py"
        mock_git_repo.return_value = mock_repo
        mock_subprocess_run.return_value = MagicMock()

        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name)

        self.assertEqual(files, ["file1.py", "file2.py"])
        mock_os_makedirs.assert_called_once_with("/azp/_work/1/s/NU00001_Repo_test")
        mock_os_chdir.assert_called_with("/azp/_work/1/s/NU00001_Repo_test")
        mock_git_repo.assert_called_once_with("/azp/_work/1/s/NU00001_Repo_test")
        
if __name__ == '__main__':
    unittest.main()