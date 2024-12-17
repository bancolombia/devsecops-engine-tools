import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft import Syft
from devsecops_engine_tools.engine_core.src.domain.model.component import Component

class TestSyft(unittest.TestCase):

    def _init_get_components(mock_platform, mock_install, mock_run_syft, mock_get_list_component, os_platform, command_prefix):
        mock_platform.return_value = os_platform
        mock_install.return_value = command_prefix
        mock_run_syft.return_value = "result_sbom.json"
        mock_get_list_component.return_value = [Component(name="component1", version="1.0.0"), Component(name="component2", version="2.0.0")]

        syft = Syft()
        artifact = "artifact"
        config = {
            "SYFT": {
                "SYFT_VERSION": "0.30.1",
                "OUTPUT_FORMAT": "json"
            }
        }
        service_name = "test_service"

        return syft.get_components(artifact, config, service_name)


    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._run_syft')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._install_tool_unix')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.platform.system')
    def test_get_components_linux(self, mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component):
        components = TestSyft._init_get_components(mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component, "Linux", "./syft")

        self.assertEqual(mock_install_unix.call_count, 1)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0].name, "component1")
        self.assertEqual(components[1].name, "component2")
    
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._run_syft')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._install_tool_unix')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.platform.system')
    def test_get_components_darwin(self, mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component):
        components = TestSyft._init_get_components(mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component, "Darwin", "./syft")

        self.assertEqual(mock_install_unix.call_count, 1)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0].name, "component1")
        self.assertEqual(components[1].name, "component2")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._run_syft')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._install_tool_windows')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.platform.system')
    def test_get_components_windows(self, mock_platform, mock_install_windows, mock_run_syft, mock_get_list_component):
        components = TestSyft._init_get_components(mock_platform, mock_install_windows, mock_run_syft, mock_get_list_component, "Windows", "./syft.exe")

        self.assertEqual(mock_install_windows.call_count, 1)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0].name, "component1")
        self.assertEqual(components[1].name, "component2")
    
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._run_syft')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.Syft._install_tool_unix')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.platform.system')
    def test_get_components_unsupported(self, mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component):
        components = TestSyft._init_get_components(mock_platform, mock_install_unix, mock_run_syft, mock_get_list_component, "Unsupported", None)

        self.assertEqual(mock_install_unix.call_count, 0)
        self.assertIsNone(components)


    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    def test_run_syft(self, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")

        syft = Syft()
        command_prefix = "./syft"
        artifact = "artifact"
        config = {
            "SYFT": {
                "OUTPUT_FORMAT": "json"
            }
        }
        service_name = "test_service"

        result_file = syft._run_syft(command_prefix, artifact, config, service_name)

        self.assertEqual(result_file, "test_service_SBOM.json")
    
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.logger')
    def test_run_syft_failure(self, mock_logger ,mock_subprocess_run):
        mock_subprocess_run.side_effect = [Exception("Error install"), MagicMock()]

        syft = Syft()
        command_prefix = "./syft"
        artifact = "artifact"
        config = {
            "SYFT": {
                "OUTPUT_FORMAT": "json"
            }
        }
        service_name = "test_service"

        result_file = syft._run_syft(command_prefix, artifact, config, service_name)

        self.assertIsNone(result_file)
        mock_logger.error.assert_called_once_with("Error running syft: Error install")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    def test_install_tool_unix_already_installed(self, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="./syft\n".encode())

        syft = Syft()
        command_prefix = syft._install_tool_unix("syft.tar.gz", "http://example.com/syft.tar.gz", "syft")

        self.assertEqual(command_prefix, "./syft")
        
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.tarfile.open')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.requests.get')
    def test_install_tool_unix_success(self, mock_requests_get, mock_tarfile_open, mock_subprocess_run):
        # Configurar los mocks
        mock_subprocess_run.side_effect = [MagicMock(returncode=1), MagicMock()]
        mock_requests_get.return_value.content = b"fake content"
        mock_tarfile_open.return_value.__enter__.return_value.extract.return_value = None

        # Crear instancia de Syft
        syft = Syft()

        # Llamar a la función
        command_prefix = syft._install_tool_unix("syft.tar.gz", "http://example.com/syft.tar.gz", "syft")

        # Verificar que se llamaron las funciones esperadas
        mock_requests_get.assert_called_once_with("http://example.com/syft.tar.gz", allow_redirects=True)
        mock_tarfile_open.return_value.__enter__.return_value.extract.assert_called_once_with(member=mock_tarfile_open.return_value.__enter__.return_value.getmember("syft"))
        self.assertEqual(command_prefix, "./syft")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.tarfile.open')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.requests.get')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.logger')
    def test_install_tool_unix_failure(self, mock_logger, mock_requests_get, mock_tarfile_open, mock_subprocess_run):
        # Configurar los mocks
        mock_subprocess_run.side_effect = [MagicMock(returncode=1), Exception("Installation failed")]
        mock_requests_get.return_value.content = b"fake content"
        mock_tarfile_open.return_value.__enter__.return_value.extract.side_effect = Exception("Extraction failed")

        # Crear instancia de Syft
        syft = Syft()

        # Llamar a la función y verificar que se lanza la excepción esperada
        syft._install_tool_unix("syft.tar.gz", "http://example.com/syft.tar.gz", "syft")

        mock_logger.error.assert_called_once_with("Error installing syft: Extraction failed")               

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    def test_install_tool_windows_already_installed(self, mock_subprocess_run):
        # Configurar los mocks
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="C:\\syft.exe\n".encode())

        # Crear instancia de Syft
        syft = Syft()

        # Llamar a la función
        command_prefix = syft._install_tool_windows("syft.zip", "http://example.com/syft.zip", "syft.exe")

        # Verificar que se llamaron las funciones esperadas
        self.assertEqual(command_prefix, "C:\\syft.exe")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.requests.get')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.zipfile.ZipFile')
    def test_install_tool_windows_success(self, mock_zipfile, mock_requests_get, mock_subprocess_run):
        # Configurar los mocks
        mock_subprocess_run.side_effect = [Exception("Not installed"), MagicMock()]
        mock_requests_get.return_value.content = b"fake content"
        mock_zipfile.return_value.__enter__.return_value.extract.return_value = None

        # Crear instancia de Syft
        syft = Syft()

        # Llamar a la función
        command_prefix = syft._install_tool_windows("syft.zip", "http://example.com/syft.zip", "syft.exe")

        # Verificar que se llamaron las funciones esperadas
        mock_requests_get.assert_called_once_with("http://example.com/syft.zip", allow_redirects=True)
        mock_zipfile.return_value.__enter__.return_value.extract.assert_called_once_with(member="syft.exe")
        self.assertEqual(command_prefix, "./syft.exe")

        
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.requests.get')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.zipfile.ZipFile')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.syft.syft.logger')
    def test_install_tool_windows_failure(self, mock_logger ,mock_zipfile, mock_requests_get, mock_subprocess_run):
        # Configurar los mocks
        mock_subprocess_run.side_effect = [Exception("Not installed"), Exception("Installation failed")]
        mock_requests_get.return_value.content = b"fake content"
        mock_zipfile.return_value.__enter__.return_value.extract.side_effect = Exception("Extraction failed")

        # Crear instancia de Syft
        syft = Syft()

        # Llamar a la función y verificar que se lanza la excepción esperada
        syft._install_tool_windows("syft.zip", "http://example.com/syft.zip", "syft.exe")

        mock_logger.error.assert_called_once_with("Error installing syft: Extraction failed")

