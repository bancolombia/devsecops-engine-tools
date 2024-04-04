import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.git.git_run import (
    GitRun,
)

class TestGitRun(unittest.TestCase):
    def setUp(self):
        self.git_run = GitRun()
        
    # @patch('subprocess.run')
    # def test_get_files_pull_request_success(self, mock_subprocess):
    #     # Mock subprocess.run() para simular el comportamiento exitoso
    #     mock_subprocess.return_value.returncode = 0
    #     mock_subprocess.return_value.stdout = b'file1.py\nruta/file2.py\n'

    #     git_run = GitRun()

    #     # Simular datos de entrada
    #     sys_working_dir = '/path/to/working/dir'
    #     target_branch = 'main'
    #     config_target_branch = ['main', 'develop']

    #     # Ejecutar el método bajo prueba
    #     files_pr = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

    #     # Verificar que se obtienen los archivos correctamente
    #     self.assertEqual(files_pr, ['file1.py','ruta/file2.py'])

    # @patch('subprocess.run')
    # def test_get_files_pull_request_error(self, mock_subprocess):
    #     # Mock subprocess.run() para simular un error al obtener las ramas
    #     mock_subprocess.return_value.returncode = 1
    #     mock_subprocess.return_value.stderr = b'fatal: not a git repository\n'

    #     git_run = GitRun()

    #     # Simular datos de entrada
    #     sys_working_dir = '/path/to/working/dir'
    #     target_branch = 'main'
    #     config_target_branch = ['main', 'develop']

    #     # Ejecutar el método bajo prueba
    #     files_pr = git_run.get_files_pull_request(sys_working_dir, target_branch, config_target_branch)

    #     # Verificar que no se obtienen archivos en caso de error
    #     self.assertEqual(files_pr, [])
    
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


if __name__ == '__main__':
    unittest.main()
