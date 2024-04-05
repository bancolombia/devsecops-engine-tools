import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.git.git_run import (
    GitRun,
)

class TestGitRun(unittest.TestCase):
    def setUp(self):
        self.git_run = GitRun()
    
    @patch('subprocess.run')
    def test_get_files_pull_request_success(self, mock_subprocess_run):
        git_run = GitRun()
        sys_working_dir = '/path/to/working/dir'
        target_branch = 'main'
        config_target_branch = ['main', 'develop']

        mock_subprocess_run.side_effect = [
            MagicMock(returncode=0, stdout=b'remotes/origin/main\nremotes/origin/commit_id'),
            MagicMock(returncode=0, stdout=b'file1.txt\nfile2.txt')
        ]

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

        self.assertEqual(files, ['file1.txt', 'file2.txt'])

    @patch('subprocess.run')
    def test_get_files_pull_request_no_target_branch(self, mock_subprocess_run):
        git_run = GitRun()
        sys_working_dir = '/path/to/working/dir'
        target_branch = 'trunk'
        config_target_branch = ['main', 'develop']

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

        self.assertEqual(files, [])

    @patch('subprocess.run')
    def test_get_files_pull_request_fail_fetch(self, mock_subprocess_run):
        git_run = GitRun()
        sys_working_dir = '/path/to/working/dir'
        target_branch = 'main'
        config_target_branch = ['main', 'develop']

        mock_subprocess_run.side_effect = [
            MagicMock(returncode=1, stdout=b'', stderr=b'fatal: refusing to merge unrelated histories'),
            MagicMock(returncode=0, stdout=b'')
        ]

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

        self.assertEqual(files, [])

    @patch('subprocess.run')
    def test_get_files_pull_request_fail_diff(self, mock_subprocess_run):
        git_run = GitRun()
        sys_working_dir = '/path/to/working/dir'
        target_branch = 'main'
        config_target_branch = ['main', 'develop']

        mock_subprocess_run.side_effect = [
            MagicMock(returncode=0, stdout=b'remotes/origin/main\nremotes/origin/commit_id', stderr=b''),
            MagicMock(returncode=1, stdout=b'', stderr=b'fatal: refusing to merge unrelated histories')
        ]

        files = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

        self.assertEqual(files, [])
if __name__ == '__main__':
    unittest.main()
