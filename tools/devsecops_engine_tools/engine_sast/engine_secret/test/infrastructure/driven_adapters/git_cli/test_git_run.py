import os
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
        source_branch = "refs/heads/feature/branch"

        mock_subprocess_run.side_effect = Exception("Simulated exception")
        
        git_run = GitRun()
        files = git_run.get_files_pull_request(sys_working_dir, target_branch, source_branch)
        
        self.assertEqual(files, [])
        
    @patch('subprocess.run')
    @patch('os.chdir')
    def test_get_files_pull_request(self, mock_chdir, mock_subprocess_run):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        source_branch = "refs/heads/feature/branch"
   
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="file1.py\nfile2.py")
        git_run = GitRun()
        
        result = git_run.get_files_pull_request(sys_working_dir, target_branch, source_branch)

        mock_chdir.assert_called_once_with(sys_working_dir)
        mock_subprocess_run.assert_any_call(['git', 'checkout', '-b', 'feature/branch', 'origin/feature/branch'], text=True)
        mock_subprocess_run.assert_any_call(['git', 'diff', 'origin/trunk..feature/branch', '--name-only'], capture_output=True, text=True)

        self.assertEqual(result, ['file1.py', 'file2.py'])
    
    @patch('subprocess.run')
    @patch('os.chdir')
    def test_get_files_pull_request_without_files(self, mock_chdir, mock_subprocess_run):
        sys_working_dir = "/azp/_work/1/s"
        target_branch = "trunk"
        source_branch = "refs/heads/feature/branch"
   
        mock_subprocess_run.return_value = MagicMock(returncode=1, stdout="")
        git_run = GitRun()
        
        result = git_run.get_files_pull_request(sys_working_dir, target_branch, source_branch)

        mock_chdir.assert_called_once_with(sys_working_dir)
        mock_subprocess_run.assert_any_call(['git', 'checkout', '-b', 'feature/branch', 'origin/feature/branch'], text=True)
        mock_subprocess_run.assert_any_call(['git', 'diff', 'origin/trunk..feature/branch', '--name-only'], capture_output=True, text=True)

        self.assertEqual(result, None)
        
if __name__ == '__main__':
    unittest.main()