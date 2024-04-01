import unittest
from unittest.mock import patch

from mock import MagicMock

from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import TrufflehogRun

class TestTrufflehogRun(unittest.TestCase):
       
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_unix(self, mock_subprocess_run):
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Linux'})
        os_patch.start()
        self.addCleanup(os_patch.stop)
        # Configuramos un valor de retorno para el subprocess.run
        mock_subprocess_run.return_value.stdout = b'Trufflehog version 1.0.0'
        mock_subprocess_run.return_value.stderr = b''

        trufflehog_run = TrufflehogRun()
        trufflehog_run.install_tool("Linux", "/tmp")
        # Aseguramos que subprocess.run fue llamado con el comando esperado
        mock_subprocess_run.assert_called_once_with("trufflehog --version", capture_output=True, shell=True)
    
    @patch('subprocess.run')
    def test_run_install(self, mock_subprocess_run):
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install()
        mock_subprocess_run.assert_called_once_with(
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
            capture_output=True,
            shell=True
        )

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.Popen')
    def test_run_install_win(self, mock_popen):
        
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install_win("C:/temp")

        # Aseguramos que subprocess.Popen fue llamado con el comando esperado
        expected_command = (
            "powershell -Command "
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; " +
            "New-Item -Path C:/temp -ItemType Directory -Force; " +
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile C:/temp\\install_trufflehog.sh; " +
            "bash C:/temp\\install_trufflehog.sh -b C:/Trufflehog/bin; " +
            "$env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        )
        mock_popen.assert_called_once_with(expected_command, stdout=-1, stderr=-1, shell=True)
    
    @patch('builtins.open', create=True)
    @patch('concurrent.futures.ThreadPoolExecutor')
    @patch.object(TrufflehogRun, 'config_include_path')
    def test_run_tool_secret_scan(self, mock_config_include_path, mock_thread_pool_executor, mock_open):
        # Configurar mock de ThreadPoolExecutor
        mock_executor = MagicMock()
        mock_executor_map_result = ['{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}\n']
        mock_executor.map.return_value = mock_executor_map_result
        mock_thread_pool_executor.return_value.__enter__.return_value = mock_executor

        # Configurar mock de config_include_path
        mock_config_include_path.return_value = ['/usr/temp/includePath0.txt']

        # Configurar parámetros de prueba
        files_commits = ['/usr/file1.py', '/usr/file2.py']
        exclude_paths = ['.git', 'gradle']
        agent_os = 'Windows'
        agent_work_folder = '/usr/temp'
        sys_working_dir = '/usr/local'
        num_threads = 4

        # Crear instancia de la clase
        trufflehog_run = TrufflehogRun()

        # Llamar a la función bajo prueba
        result = trufflehog_run.run_tool_secret_scan(files_commits, exclude_paths, agent_os, agent_work_folder, sys_working_dir, num_threads)

        # Verificar el resultado
        expected_result = [
            {"SourceMetadata": {"Data": {"Filesystem": {"file": "/usr/bin/local/file1.txt", "line": 1}}}, "SourceID": 1,
            "SourceType": 15, "SourceName": "trufflehog - filesystem", "DetectorType": 17, "DetectorName": "URI",
            "DecoderName": "BASE64", "Verified": False,
            "Raw": "https://admin:admin@the-internet.herokuapp.com",
            "RawV2": "https://admin:admin@the-internet.herokuapp.com/basic_auth",
            "Redacted": "https://admin:********@the-internet.herokuapp.com", "ExtraData": None,
            "StructuredData": None}]
        self.assertEqual(result, expected_result)

    @patch('builtins.open', create=True)
    def test_config_include_path(self, mock_open):
        # Crear instancia de la clase
        trufflehog_run = TrufflehogRun()

        # Llamar a la función bajo prueba
        result = trufflehog_run.config_include_path(['/usr/file1.py', '/usr/file2.py'], '/usr/temp')

        # Verificar el resultado
        expected_result = ['/usr/temp/includePath0.txt', '/usr/temp/includePath1.txt']
        self.assertEqual(result, expected_result)

    @patch('subprocess.run')
    def test_run_trufflehog(self, mock_subprocess_run):
        # Configurar mock
        mock_subprocess_run.return_value.stdout.strip.return_value = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'

        # Crear instancia de la clase
        trufflehog_run = TrufflehogRun()

        # Llamar a la función bajo prueba
        result = trufflehog_run.run_trufflehog('trufflehog', '/usr/local', '/usr/temp/excludedPath.txt', '/usr/temp/includePath0.txt')

        # Verificar el resultado
        expected_result = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        self.assertEqual(result, expected_result)
        
if __name__ == '__main__':
    unittest.main()