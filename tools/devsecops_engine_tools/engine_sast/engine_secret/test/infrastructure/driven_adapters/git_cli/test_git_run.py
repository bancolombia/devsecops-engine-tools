import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.git_cli.git_run import GitRun

class TestGitRun(unittest.TestCase):
    @patch('os.makedirs')
    @patch('os.chdir')
    @patch('subprocess.run')
    def test_get_files_pull_request_Exception(self, mock_subprocess_run, mock_os_chdir, mock_os_makedirs):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"
        repository_provider = "TfsGit"

        mock_subprocess_run.side_effect = Exception("Simulated exception")
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name, repository_provider)
        
        self.assertEqual(files, [])
        
    @patch('os.path.exists')
    @patch('os.makedirs')
    @patch('os.chdir')
    @patch('subprocess.run')
    def test_get_files_pull_request_path_no_exist(self, mock_subprocess_run, mock_os_chdir, mock_os_makedirs, mock_path_exists):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"
        repository_provider = "TfsGit"

        mock_subprocess_run.return_value = MagicMock()
        mock_subprocess_run.return_value = "file1.py\nfile2.py"
        mock_path_exists.return_value = False
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name, repository_provider)

        self.assertEqual(files, [])
        mock_os_makedirs.assert_called_once_with("/azp/_work/1/s/NU00001_Repo_test")
        mock_os_chdir.assert_called_with("/azp/_work/1/s/NU00001_Repo_test")
        
    @patch('os.path.exists')
    def test_get_files_pull_request_path_exist(self, mock_path_exists):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"
        repository_provider = "TfsGit"
   
        mock_path_exists.return_value = True
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name, repository_provider)

        self.assertEqual(files, [])
        
    def test_get_files_pull_request_no_target_branch(self):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "release"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"
        repository_provider = "TfsGit"
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name, repository_provider)

        self.assertEqual(files, [])
        
    def test_get_files_pull_request_github_provider(self):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        access_token = "ABCDEFG123456"
        collection_uri = "https://dev.azure.com/orgName"
        team_project = "team_project"
        repository_name = "NU00001_Repo_test"
        repository_provider = "GitHub"
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch,
                                               access_token, collection_uri, team_project, repository_name, repository_provider)

        self.assertEqual(files, [])
if __name__ == '__main__':
    unittest.main()