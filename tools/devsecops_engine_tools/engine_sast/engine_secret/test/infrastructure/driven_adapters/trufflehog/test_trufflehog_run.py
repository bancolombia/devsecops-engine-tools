import unittest
from unittest.mock import patch

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
    
    @patch('subprocess.run')
    def test_run_tool_secret_scan_windows(self, mock_subprocess_run):
        # Configuración del mock
        mock_subprocess_run.return_value.stdout.decode.return_value = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\\\file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        
        # Crear instancia de la clase para probar
        trufflehog_run = TrufflehogRun()
        
        # Llamar a la función que estamos probando
        files_commits = ["file1"]
        exclude_path = [".git"]
        agent_os = "Windows"
        agent_work_folder = "work_folder"
        response = trufflehog_run.run_tool_secret_scan(files_commits, exclude_path, agent_os, agent_work_folder)
        
        # Verificar el resultado
        assert response == [{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":False,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":None,"StructuredData":None}]
        mock_subprocess_run.reset_mock()
        
    def test_decode_output(self):
        trufflehog_run = TrufflehogRun()
        result = []
        output = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\\\file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}\n{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\\\file2.txt"}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":15,"DetectorName":"PrivateKey","DecoderName":"PLAIN","Verified":false,"Raw":"-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----","RawV2":"","Redacted":"-----BEGIN OPENSSH PRIVATE KEY-----","ExtraData":{"cracked_encryption_passphrase":"true","encrypted":"true"},"StructuredData":null}\n'
        result = trufflehog_run.decode_output(output, result)
        expected_result = [{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":False,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":None,"StructuredData":None},{"SourceMetadata":{"Data":{"Filesystem":{"file":"C:\\file2.txt"}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":15,"DetectorName":"PrivateKey","DecoderName":"PLAIN","Verified":False,"Raw":"-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----","RawV2":"","Redacted":"-----BEGIN OPENSSH PRIVATE KEY-----","ExtraData":{"cracked_encryption_passphrase":"true","encrypted":"true"},"StructuredData":None}]
        self.assertEqual(result, expected_result)