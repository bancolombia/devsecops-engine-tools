import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.git_cli.git_run import GitRun

class TestGitRun(unittest.TestCase):
    
    @patch('os.chdir')
    @patch('git.Repo', autospec=True)
    def test_get_files_pull_request(self, mock_repo, mock_chdir):
        # Arrange
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        config_target_branch = ["trunk", "develop"]
        source_branch = "refs/heads/feature/branch"
        mock_repo_instance = MagicMock()
        mock_repo.return_value = mock_repo_instance
        mock_repo_instance.git.diff.return_value = "file1.py\nfile2.py\n"
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch)
        
        self.assertEqual(files, ["file1.py", "file2.py"])   
        
    @patch('git.Repo', autospec=True)
    def test_get_git_source_branch(self, mock_repo):
        repository = MagicMock()
        mock_repo.return_value = repository
        repository.remotes.origin.fetch.return_value = ["branch1", "branch2"]
        
        git_run = GitRun()
        source_branch = git_run.get_git_source_branch(repository, "refs/heads/source_branch")
        
        repository.remotes.origin.fetch.assert_called_once()
        self.assertEqual(source_branch, "source_branch")

    def test_get_files_pull_request_no_target_branch(self):
        git_run = GitRun()
        sys_working_dir = '/azp/_work/1/s'
        target_branch = 'trunk'
        config_target_branch = ['main', 'develop']
        source_branch = 'refs/heads/feature/branch'

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch)

        self.assertEqual(files, [])

    @patch('os.chdir')
    @patch('git.Repo')
    def test_get_files_pull_request_fail_diff(self, mock_repo, mock_chdir):
        git_run = GitRun()
        sys_working_dir = '/azp/_work/1/s'
        target_branch = 'main'
        config_target_branch = ['main', 'develop']
        source_branch = 'refs/heads/feature/branch'
 
        mock_repo.side_effect = Exception("Simulated exception")

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch, source_branch)

        self.assertEqual(files, [])
        
    @patch('os.chdir')
    @patch('git.Repo')
    def test_get_files_pull_request_no_target_branch(self, mock_repo, mock_chdir):
        repository = MagicMock()
        mock_repo.return_value = repository
        repository.remotes.origin.fetch.side_effect = Exception("Simulated exception")
        
        git_run = GitRun()
        source_branch = git_run.get_git_source_branch(repository, "refs/heads/source_branch")
        
        repository.remotes.origin.fetch.assert_called_once()
        self.assertEqual(source_branch, None)
        
if __name__ == '__main__':
    unittest.main()