import unittest
from unittest.mock import Mock, mock_open, patch
import os
import tempfile
import shutil
import subprocess
import zipfile
from pathlib import Path

import requests

from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool import ConfigTool
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.kiuwan import kiuwan_tool

class TestKiuwanToolBase(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            "user_engine_code": "test_user",
            "token_engine_code": "test_token",
            "host_engine_code": "https://test.kiuwan.com",
            "app_name": "test_app",
            "build_execution_id": "test_build_123",
            "source_branch_name": "feature/test",
            "target_branch": "master",
            "build_task": "test_task",
            "MODELOS": {"test_task": "TestModel"},
            "domain_id_engine_code": "test_domain_id"
        }
        
        self.mock_config_tool = Mock(spec=ConfigTool)
        self.mock_config_tool.target_branches = ["master", "develop"]
        self.mock_config_tool.exclude_folder = ["node_modules", "*.test.js"]
        self.mock_config_tool.data = {"SEVERITY": {"HIGH": "Critical", "MEDIUM": "High"}}
        
        self.temp_directory = tempfile.mkdtemp()
    
    def tearDown(self):
        if os.path.exists(self.temp_directory):
            shutil.rmtree(self.temp_directory)
    
    def create_kiuwan_tool(self, config=None, path_mock="/path/to/agent.sh"):
        with patch.object(kiuwan_tool.KiuwanTool, '_find_or_download_kiuwan_agent', return_value=path_mock):
            return kiuwan_tool.KiuwanTool(config or self.config)


class TestKiuwanToolInit(TestKiuwanToolBase):
    
    def test_init_with_complete_config(self):
        with patch.object(kiuwan_tool.KiuwanTool, '_find_or_download_kiuwan_agent', return_value='/path/to/agent.sh'):
            tool = kiuwan_tool.KiuwanTool(self.config)
            
            self.assertEqual(tool.user, "test_user")
            self.assertEqual(tool.password, "test_token")
            self.assertEqual(tool.base_url, "https://test.kiuwan.com")
            self.assertEqual(tool.build_execution_id, "test_build_123")
            self.assertEqual(tool.source_branch_name, "feature/test")
            self.assertEqual(tool.target_branch, "master")
            self.assertEqual(tool.build_task, "test_task")
            self.assertEqual(tool.modelo_regla, "TestModel")
            self.assertEqual(tool.domain_id, "test_domain_id")
            self.assertEqual(tool.repository_name, "")
            self.assertEqual(tool.kiuwan_agent_path, '/path/to/agent.sh')
    
    def test_init_with_partial_config(self):
        partial_config = {
            "user_engine_code": "user",
            "host_engine_code": "https://test.com"
        }
        with patch.object(kiuwan_tool.KiuwanTool, '_find_or_download_kiuwan_agent', return_value='/path/to/agent.sh'):
            tool = kiuwan_tool.KiuwanTool(partial_config)
            
            self.assertEqual(tool.user, "user")
            self.assertEqual(tool.password, "")
            self.assertEqual(tool.modelo_regla, "General")
            self.assertEqual(tool.kiuwan_agent_path, '/path/to/agent.sh')


class TestFindOrDownloadKiuwanAgent(TestKiuwanToolBase):
    
    @patch('platform.system')
    def test_find_agent_windows(self, mock_system):
        mock_system.return_value = "Windows"
        tool = self.create_kiuwan_tool()
        tool._search_agent_script = Mock(return_value="/path/to/agent.cmd")
        
        result = tool._find_or_download_kiuwan_agent()
        
        self.assertEqual(result, "/path/to/agent.cmd")
        tool._search_agent_script.assert_called_with("agent.cmd")
    
    @patch('platform.system')
    def test_find_agent_linux(self, mock_system):
        mock_system.return_value = "Linux"
        tool = self.create_kiuwan_tool()
        tool._search_agent_script = Mock(return_value="/path/to/agent.sh")
        
        result = tool._find_or_download_kiuwan_agent()
        
        self.assertEqual(result, "/path/to/agent.sh")
        tool._search_agent_script.assert_called_with("agent.sh")
    
    @patch('platform.system')
    def test_find_agent_macos(self, mock_system):
        mock_system.return_value = "Darwin"
        tool = self.create_kiuwan_tool()
        tool._search_agent_script = Mock(return_value="/path/to/agent.sh")
        
        result = tool._find_or_download_kiuwan_agent()
        
        self.assertEqual(result, "/path/to/agent.sh")
        tool._search_agent_script.assert_called_with("agent.sh")
    
    @patch('platform.system')
    def test_unsupported_os(self, mock_system):
        mock_system.return_value = "UnsupportedOS"
        
        with self.assertRaises(RuntimeError) as context:
            kiuwan_tool.KiuwanTool(self.config)
        
        self.assertIn("Unsupported OS", str(context.exception))
    
    @patch('platform.system')
    def test_download_agent_when_not_found(self, mock_system):
        mock_system.return_value = "Linux"
        tool = self.create_kiuwan_tool()
        tool._search_agent_script = Mock(side_effect=["", "/path/to/agent.sh"])
        tool._download_and_extract_kiuwan = Mock()
        
        result = tool._find_or_download_kiuwan_agent()
        
        self.assertEqual(result, "/path/to/agent.sh")
        tool._download_and_extract_kiuwan.assert_called_once()
    
    @patch('platform.system')
    def test_agent_not_found_after_download(self, mock_system):
        mock_system.return_value = "Linux"
        tool = self.create_kiuwan_tool()
        tool._search_agent_script = Mock(return_value="")
        tool._download_and_extract_kiuwan = Mock()
        
        with self.assertRaises(FileNotFoundError) as context:
            tool._find_or_download_kiuwan_agent()
        
        self.assertIn("agent.sh was not found", str(context.exception))


class TestSearchAgentScript(TestKiuwanToolBase):
    
    def test_search_agent_script_found(self):
        tool = self.create_kiuwan_tool()
        # Crear estructura de directorios
        Path(os.path.join(self.temp_directory, "tools")).mkdir(parents=True, exist_ok=True)
        agent_path = os.path.join(self.temp_directory, "tools", "agent.sh")
        with open(agent_path, 'w') as f:
            f.write("#!/bin/bash")
        
        tool.working_directory = self.temp_directory
        result = tool._search_agent_script("agent.sh")
        
        self.assertEqual(result, agent_path)
    
    def test_search_agent_script_not_found(self):
        tool = self.create_kiuwan_tool()
        tool.working_directory = self.temp_directory
        result = tool._search_agent_script("agent.sh")
        
        self.assertEqual(result, "")


class TestSetExecutionPermissions(TestKiuwanToolBase):
    
    def setUp(self):
        
        self.config = {
            "user_engine_code": "test_user",
            "token_engine_code": "test_token",
            "host_engine_code": "https://test.kiuwan.com",
            "app_name": "test_app",
            "build_execution_id": "test_build_123",
            "source_branch_name": "feature/test",
            "target_branch": "master",
            "build_task": "test_task",
            "MODELOS": {"test_task": "TestModel"},
            "domain_id_engine_code": "test_domain_id"
        }
        
        self.mock_config_tool = Mock(spec=ConfigTool)
        self.mock_config_tool.target_branches = ["master", "develop"]
        self.mock_config_tool.exclude_folder = ["node_modules", "*.test.js"]
        self.mock_config_tool.data = {"SEVERITY": {"HIGH": "Critical", "MEDIUM": "High"}}
        
        self.temp_directory = tempfile.mkdtemp()
        Path(os.path.join(self.temp_directory, "tools")).mkdir(parents=True, exist_ok=True)
        self.agent_path = os.path.join(self.temp_directory, "tools", "agent.sh")
        with open(self.agent_path, 'w') as f:
            f.write("#!/bin/bash")

            
    def tearDown(self):
        if os.path.exists(self.temp_directory):
            shutil.rmtree(self.temp_directory)
    
    @patch('platform.system')
    def test_set_execution_permissions_linux(self, mock_system):
        mock_system.return_value = "Linux"
                
        tool = self.create_kiuwan_tool()

        files = [self.agent_path, f'{os.path.join(self.temp_directory, "tools", "file.txt")}']
        tool._set_execution_permissions(files)
        permission_sh = os.access(files[0], os.X_OK)
        permission_txt = os.access(files[1], os.X_OK)
        self.assertTrue(permission_sh)
        self.assertFalse(permission_txt)
        self.assertNotEqual(permission_sh, permission_txt)
        
    @patch('platform.system')
    def test_set_execution_permissions_darwin(self, mock_system):
        mock_system.return_value = "darwin"
                
        tool = self.create_kiuwan_tool()

        files = [self.agent_path, f'{os.path.join(self.temp_directory, "tools", "file.txt")}']
        tool._set_execution_permissions(files)
        permission_sh = os.access(files[0], os.X_OK)
        permission_txt = os.access(files[1], os.X_OK)
        self.assertTrue(permission_sh)
        self.assertFalse(permission_txt)
        self.assertNotEqual(permission_sh, permission_txt)


class TestExtractZip(TestKiuwanToolBase):
    
    def test_extract_zip_success(self):
        self.temp_directory = tempfile.mkdtemp()
        # Rutas locales
        bin_dir = os.path.join(self.temp_directory, "KiuwanLocalAnalyzer", "bin")
        lib_dir = os.path.join(self.temp_directory, "KiuwanLocalAnalyzer", "lib")
        Path(bin_dir).mkdir(parents=True, exist_ok=True)
        Path(lib_dir).mkdir(parents=True, exist_ok=True)

        agent_sh_path = os.path.join(bin_dir, "agent.sh")
        kiuwan_jar_path = os.path.join(lib_dir, "kiuwan.jar")

        Path(agent_sh_path).write_text("#!/bin/bash")
        Path(kiuwan_jar_path).write_text("fake jar content", encoding="utf-8")

        # Crear ZIP
        zip_path = os.path.join(self.temp_directory, "test_kiuwan.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # ✅ Directorios (opcionales, pero ayudan)
            zipf.writestr("KiuwanLocalAnalyzer/", "")
            zipf.writestr("KiuwanLocalAnalyzer/bin/", "")
            zipf.writestr("KiuwanLocalAnalyzer/lib/", "")

            # Archivos
            info = zipfile.ZipInfo("KiuwanLocalAnalyzer/bin/agent.sh")
            info.external_attr = 0o755 << 16
            with open(agent_sh_path, 'rb') as f:
                zipf.writestr(info, f.read())

            info = zipfile.ZipInfo("KiuwanLocalAnalyzer/lib/kiuwan.jar")
            info.external_attr = 0o644 << 16
            with open(kiuwan_jar_path, 'rb') as f:
                zipf.writestr(info, f.read())

        # Imprimir contenido del ZIP para depurar
        print("\n=== ZIP CONTENT ===")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for f in zf.namelist():
                print(f"  {f}")
        print("==================\n")

        # Preparar herramienta
        tool = self.create_kiuwan_tool()
        extracted_dir = os.path.join(self.temp_directory, "extracted")
        tool.working_directory = extracted_dir

        # Llamar al método
        result = tool._extract_zip(zip_path)

        # Validar
        self.assertEqual(len(result), 2)
        self.assertTrue(os.path.exists(os.path.join(extracted_dir, "bin", "agent.sh")))
        self.assertTrue(os.path.exists(os.path.join(extracted_dir, "lib", "kiuwan.jar")))

    
    @patch('zipfile.ZipFile')
    def test_extract_zip_error(self, mock_zipfile):
        mock_zipfile.side_effect = Exception("Zip error")
        
        tool = self.create_kiuwan_tool()
        with self.assertRaises(Exception) as context:
            tool._extract_zip("/path/to/zip")
        
        self.assertIn("Zip error", str(context.exception))


class TestDownloadAndExtractKiuwan(TestKiuwanToolBase):
    
    @patch('urllib.request.urlretrieve')
    @patch('os.remove')
    def test_download_and_extract_success(self, mock_remove, mock_urlretrieve):
        tool = self.create_kiuwan_tool()
        tool._extract_zip = Mock(return_value=["/path/to/agent.sh"])
        tool._set_execution_permissions = Mock()
        
        tool._download_and_extract_kiuwan()
        
        mock_urlretrieve.assert_called_once()
        tool._extract_zip.assert_called_once()
        tool._set_execution_permissions.assert_called_once_with(["/path/to/agent.sh"])
        mock_remove.assert_called_once()
    
    @patch('urllib.request.urlretrieve')
    def test_download_error(self, mock_urlretrieve):
        mock_urlretrieve.side_effect = Exception("Download failed")
        
        tool = self.create_kiuwan_tool()
        with self.assertRaises(RuntimeError) as context:
            tool._download_and_extract_kiuwan()
        
        self.assertIn("Error downloading or extracting", str(context.exception))


class TestValidateTargetBranch(TestKiuwanToolBase):
    
    def test_validate_target_branch_allowed(self):
        tool = self.create_kiuwan_tool()
        tool.target_branch = "master"
        result = tool._validate_target_branch(self.mock_config_tool)
        self.assertTrue(result)
    
    def test_validate_target_branch_not_allowed(self):
        tool = self.create_kiuwan_tool()
        tool.target_branch = "forbidden_branch"
        
        result = tool._validate_target_branch(self.mock_config_tool)
        
        self.assertFalse(result)
    
    def test_validate_target_branch_empty_list(self):
        tool = self.create_kiuwan_tool()
        config_tool = Mock(spec=ConfigTool)
        config_tool.target_branches = []
        
        result = tool._validate_target_branch(config_tool)
        
        self.assertTrue(result)
    
    def test_validate_target_branch_none(self):
        tool = self.create_kiuwan_tool()
        config_tool = Mock(spec=ConfigTool)
        config_tool.target_branches = None
        
        result = tool._validate_target_branch(config_tool)
        
        self.assertTrue(result)


class TestPrepareScanDirectory(TestKiuwanToolBase):
    
    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('shutil.copy2')
    @patch('os.path.relpath')
    def test_prepare_scan_directory_pr_files(self, mock_relpath, mock_copy2, mock_exists, mock_makedirs):
        mock_exists.return_value = True
        mock_relpath.return_value = "src/file.py"
        self.mock_config_tool.exclude_folder = []
        
        tool = self.create_kiuwan_tool()
        pr_files = ["/repo/src/file.py", "/repo/src/test.py"]
        
        result = tool._prepare_scan_directory(
            None, pr_files, self.temp_directory, self.mock_config_tool
        )
        
        expected_path = os.path.join(self.temp_directory, "temp_folder_to_scan")
        self.assertEqual(result, expected_path)
        mock_makedirs.assert_called()
        self.assertEqual(mock_copy2.call_count, 2)
    
    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('shutil.copytree')
    def test_prepare_scan_directory_folder_to_scan(self, mock_copytree, mock_exists, mock_makedirs):
        mock_exists.return_value = True
        self.mock_config_tool.exclude_folder = []
        
        tool = self.create_kiuwan_tool()
        folder_to_scan = "/source/folder"
        
        result = tool._prepare_scan_directory(
            folder_to_scan, [], self.temp_directory, self.mock_config_tool
        )
        
        expected_path = os.path.join(self.temp_directory, "temp_folder_to_scan")
        self.assertEqual(result, expected_path)
        mock_copytree.assert_called_with(folder_to_scan, expected_path, dirs_exist_ok=True)
    
    @patch('os.makedirs')
    def test_prepare_scan_directory_with_exclusions(self, mock_makedirs):
        self.mock_config_tool.exclude_folder = ["node_modules"]
        
        tool = self.create_kiuwan_tool()
        tool._handle_exclusions = Mock()
        
        result = tool._prepare_scan_directory(
            None, [], self.temp_directory, self.mock_config_tool
        )
        
        tool._handle_exclusions.assert_called_once()


class TestHandleExclusions(TestKiuwanToolBase):
    
    @patch('os.walk')
    @patch('os.makedirs')
    @patch('shutil.move')
    @patch('os.path.relpath')
    def test_handle_exclusions_directory(self, mock_relpath, mock_move, mock_makedirs, mock_walk):
        mock_walk.return_value = [
            ("/scan", ["node_modules", "src"], ["file.py"]),
            ("/scan/src", [], ["test.py"])
        ]
        mock_relpath.return_value = "node_modules"
        
        tool = self.create_kiuwan_tool()
        tool._matches_exclude_pattern = Mock(side_effect=lambda name, pattern: name == "node_modules")
        
        tool._handle_exclusions("/scan", ["node_modules"], "/agent")
        
        mock_move.assert_called()
        mock_makedirs.assert_called()
    
    @patch('os.walk')
    @patch('os.makedirs')
    @patch('shutil.move')
    @patch('os.path.relpath')
    def test_handle_exclusions_file(self, mock_relpath, mock_move, mock_makedirs, mock_walk):
        mock_walk.return_value = [
            ("/scan", [], ["test.spec.js", "app.js"])
        ]
        mock_relpath.return_value = "test.spec.js"
        
        tool = self.create_kiuwan_tool()
        tool._matches_exclude_pattern = Mock(side_effect=lambda name, pattern: "test" in name)
        
        tool._handle_exclusions("/scan", ["*test*"], "/agent")
        
        mock_move.assert_called()


class TestMatchesExcludePattern(TestKiuwanToolBase):
    
    def test_matches_exclude_pattern_fnmatch(self):
        tool = self.create_kiuwan_tool()
        result = tool._matches_exclude_pattern("test.spec.js", "*.spec.js")
        self.assertTrue(result)
    
    def test_matches_exclude_pattern_substring(self):
        tool = self.create_kiuwan_tool()
        result = tool._matches_exclude_pattern("node_modules", "node_modules")
        self.assertTrue(result)
    
    def test_matches_exclude_pattern_no_match(self):
        tool = self.create_kiuwan_tool()
        result = tool._matches_exclude_pattern("app.js", "*.spec.js")
        self.assertFalse(result)


class TestDetermineAnalysisType(TestKiuwanToolBase):
    
    @patch('requests.get')
    def test_determine_analysis_type_baseline(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"name": "other_app"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        tool.repository_name = "new_app"
        result = tool._determine_analysis_type()
        
        self.assertEqual(result, "baseline")
    
    @patch('requests.get')
    def test_determine_analysis_type_delivery(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"name": "existing_app"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        tool.repository_name = "existing_app"
        result = tool._determine_analysis_type()
        
        self.assertEqual(result, "delivery")


class TestExecuteKiuwanScan(TestKiuwanToolBase):
    
    @patch('subprocess.run')
    def test_execute_kiuwan_scan_baseline_success(self, mock_run):
        mock_result = Mock()
        mock_result.stdout = "Analysis completed"
        mock_run.return_value = mock_result
        
        tool = self.create_kiuwan_tool()
        result = tool._execute_kiuwan_scan("baseline", "/scan/dir")
        
        self.assertEqual(result, mock_result)
        # Verificar que se llamó con los argumentos correctos
        call_args = mock_run.call_args[0][0]
        self.assertIn("--create", call_args)
        self.assertIn("--analysis-scope", call_args)
        self.assertIn("baseline", call_args)
    
    @patch('subprocess.run')
    def test_execute_kiuwan_scan_delivery_success(self, mock_run):
        mock_result = Mock()
        mock_run.return_value = mock_result
        
        tool = self.create_kiuwan_tool()
        result = tool._execute_kiuwan_scan("delivery", "/scan/dir")
        
        self.assertEqual(result, mock_result)
        call_args = mock_run.call_args[0][0]
        self.assertIn("completeDelivery", call_args)
        self.assertIn("--change-request", call_args)
    
    @patch('subprocess.run')
    def test_execute_kiuwan_scan_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Error")
        
        tool = self.create_kiuwan_tool()
        result = tool._execute_kiuwan_scan("baseline", "/scan/dir")
        
        self.assertEqual(result["status"], "failed")
        self.assertIn("Error", result["output"])


class TestValidateResults(TestKiuwanToolBase):
    
    @patch('requests.get')
    def test_validate_results_baseline_success(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"applicationBusinessValue": "LOW"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        #No debería lanzar excepción
        try:
            tool._validate_results("baseline")
        except Exception:
            self.fail("_validate_results raised an unexpected exception")
    
    @patch('requests.get')
    def test_validate_results_baseline_critical(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"applicationBusinessValue": "CRITICAL"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        tool._validate_results("baseline")
        mock_get.assert_called_once()
    
    @patch('requests.get')
    def test_validate_results_delivery_success(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"auditResult": "OK"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        try:
            tool._validate_results("delivery")
        except Exception:
            self.fail("_validate_results raised an unexpected exception")
    
    @patch('requests.get')
    def test_validate_results_delivery_failed(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = [{"auditResult": "FAIL"}]
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        tool._validate_results("delivery")
        mock_get.assert_called_once()

class TestFetchLastAnalysis(TestKiuwanToolBase):
    
    @patch('requests.get')
    @patch('time.sleep')
    def test_fetch_last_analysis_finished(self, mock_sleep, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = {"analysisStatus": "FINISHED"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        result = tool._fetch_last_analysis()
        
        self.assertEqual(result["analysisStatus"], "FINISHED")
        mock_sleep.assert_not_called()
    
    @patch('requests.get')
    @patch('time.sleep')
    def test_fetch_last_analysis_waiting(self, mock_sleep, mock_get):
        responses = [
            {"analysisStatus": "RUNNING"},
            {"analysisStatus": "RUNNING"},
            {"analysisStatus": "FINISHED"}
        ]
        mock_response = Mock()
        mock_response.json.side_effect = responses
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        result = tool._fetch_last_analysis()
        
        self.assertEqual(result["analysisStatus"], "FINISHED")
        self.assertEqual(mock_sleep.call_count, 2)
    
    @patch('requests.get')
    def test_fetch_last_analysis_error(self, mock_get):
        mock_get.side_effect = RuntimeError("Failed to fetch last analysis")
        
        tool = self.create_kiuwan_tool()
        with self.assertRaises(RuntimeError) as context:
            tool._fetch_last_analysis()
        
        self.assertIn("Failed to fetch last analysis", str(context.exception))


class TestFetchDefectsForAnalysis(TestKiuwanToolBase):
    
    @patch('requests.get')
    def test_fetch_defects_single_page(self, mock_get):
        mock_response = Mock()
        mock_response.json.return_value = {
            "defects": [{"id": 1}, {"id": 2}],
            "defects_count": 2
        }
        mock_response.raise_for_status = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        tool = self.create_kiuwan_tool()
        result = tool._fetch_defects_for_analysis("analysis123")
        
        self.assertEqual(len(result["defects"]), 2)
        self.assertEqual(mock_get.call_count, 1)
    
    @patch('requests.get')
    def test_fetch_defects_multiple_pages(self, mock_get):
        # Primera página
        first_response = Mock()
        first_response.json.return_value = {
            "defects": [{"id": i} for i in range(5000)],
            "defects_count": 7000
        }
        first_response.raise_for_status = Mock()
        first_response.status_code = 200
        
        # Segunda página
        second_response = Mock()
        second_response.json.return_value = {
            "defects": [{"id": i} for i in range(5000, 7000)]
        }
        second_response.status_code = 200
        
        mock_get.side_effect = [first_response, second_response]
        
        tool = self.create_kiuwan_tool()
        result = tool._fetch_defects_for_analysis("analysis123")
        
        self.assertEqual(len(result["defects"]), 7000)
        self.assertEqual(mock_get.call_count, 2)
    
    @patch('requests.get')
    def test_fetch_defects_error(self, mock_get):
        mock_get.side_effect = RuntimeError("Failed to fetch defects")
        
        tool = self.create_kiuwan_tool()
        with self.assertRaises(RuntimeError) as context:
            tool._fetch_defects_for_analysis("analysis123Test")
        
        self.assertIn("Failed to fetch defects", str(context.exception))


class TestMapDefectsToFindings(TestKiuwanToolBase):
    
    @patch('devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.kiuwan.kiuwan_deserealizator.KiuwanDeserealizator.get_findings')
    def test_map_defects_to_findings(self, mock_get_findings):
        last_analysis = {"analysisCode": "123"}
        defects_data = {"defects": []}
        severity_mapper = {"HIGH": "Critical"}
        expected_findings = [Mock()]
        
        mock_get_findings.return_value = expected_findings
        
        tool = self.create_kiuwan_tool()
        result = tool._map_defects_to_findings(
            last_analysis, defects_data, "123", severity_mapper
        )
        
        self.assertEqual(result, expected_findings)
        mock_get_findings.assert_called_once_with(
            last_analysis, defects_data, "123", severity_mapper
        )



class TestGetKiuwanInstance(unittest.TestCase):
    
    @patch('devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.kiuwan.kiuwan_tool.KiuwanTool')
    def test_get_kiuwan_instance(self, mock_kiuwan_tool):
        # Mock dependencies
        devops_platform_gateway = Mock()
        
        # Mock configuration
        kiuwan_config = {
            "KIUWAN":{
                "SERVER": {
                    "BASE_URL": "https://test.kiuwan.com",
                    "USER": "test_user",
                    "DOMAIN_ID": "test_domain"
                },
                "MODELOS": {"task1": "Model1"}
            }
        }
        
        devops_platform_gateway.get_remote_config.return_value = kiuwan_config
        devops_platform_gateway.get_variable.side_effect = lambda var: {
            "app_name": "test_app",
            "build_execution_id": "build123",
            "branch_name": "feature/test",
            "target_branch": "main",
            "build_task": "task1"
        }.get(var)
        
        dict_args = {
            "remote_config_repo": "config_repo",
            "remote_config_branch": "main",
            "token_engine_code": "test_token",
            "tool": "KIUWAN"
        }
        
        # Mock KiuwanTool instance
        mock_instance = Mock()
        mock_kiuwan_tool.return_value = mock_instance
        
        result = kiuwan_tool.get_kiuwan_instance(dict_args, devops_platform_gateway)
        
        self.assertEqual(result, mock_instance)
        devops_platform_gateway.get_remote_config.assert_called_once()
        mock_kiuwan_tool.assert_called_once()
        
        # Verificar configuración pasada
        call_args = mock_kiuwan_tool.call_args[0][0]
        self.assertEqual(call_args["host_engine_code"], "https://test.kiuwan.com")
        self.assertEqual(call_args["user_engine_code"], "test_user")
        self.assertEqual(call_args["token_engine_code"], "test_token")


class TestDownloadKiuwanCsvOfficial(TestKiuwanToolBase):

    def setUp(self):
        super().setUp()
        self.tool = self.create_kiuwan_tool()

    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open)
    def test_download_csv_success(self, mock_file, mock_requests_get):
        # Configurar respuesta simulada
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Type": "text/csv"}
        mock_response.iter_content = Mock(return_value=[b"sep=,\n", b"Vulnerability,Line\n", b"XSS,42\n"])

        mock_requests_get.return_value = mock_response

        analysis_code = "ANALYSIS123"
        output_path = "kiuwan_findings.csv"

        # Ejecutar el método
        result = self.tool._download_kiuwan_csv_official(analysis_code, output_path)

        # Construir URL esperada
        expected_url = (
            f"{self.tool.base_url}/applications/analysis/vulnerabilities/export?"
            f"application={self.tool.repository_name}&code=ANALYSIS123&type=CSV"
        )

        # Verificaciones
        mock_requests_get.assert_called_once()
        call_args = mock_requests_get.call_args
        self.assertEqual(call_args.args[0], expected_url)
        self.assertEqual(call_args.kwargs["auth"], (self.tool.user, self.tool.password))
        self.assertIn("stream", call_args.kwargs)
        self.assertTrue(call_args.kwargs["stream"])

        # Verificar que se abrió el archivo y se escribió
        mock_file.assert_called_once_with(output_path, "wb")
        mock_file().write.assert_any_call(b"sep=,\n")
        mock_file().write.assert_any_call(b"Vulnerability,Line\n")
        mock_file().write.assert_any_call(b"XSS,42\n")

        # Verificar retorno
        self.assertEqual(result, output_path)

    @patch("requests.get")
    def test_download_csv_non_csv_content_type_warning(self, mock_requests_get):
        # Simular respuesta sin Content-Type CSV
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Type": "application/octet-stream"}  # No es CSV
        mock_response.iter_content = Mock(return_value=[b"data"])

        mock_requests_get.return_value = mock_response

        with patch("builtins.open", mock_open()) as mock_file:
            with patch.object(kiuwan_tool.logger,"warning") as mock_warn:
                result = self.tool._download_kiuwan_csv_official("ANALYSIS123", "kiuwan_findings.csv")
                mock_warn.assert_called_once()
                self.assertEqual(result, "kiuwan_findings.csv")

    @patch("requests.get")
    def test_download_csv_request_failed(self, mock_requests_get):
        # Simular error en la solicitud
        mock_requests_get.side_effect = requests.RequestException("Connection timeout")

        with self.assertRaises(RuntimeError) as context:
            self.tool._download_kiuwan_csv_official("ANALYSIS123", "kiuwan_findings.csv")

        self.assertIn("Error downloading Kiuwan CSV", str(context.exception))
        self.assertIn("Connection timeout", str(context.exception))

    @patch("requests.get")
    def test_download_csv_http_error(self, mock_requests_get):
        # Simular error 404
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_requests_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            self.tool._download_kiuwan_csv_official("ANALYSIS123", "kiuwan_findings.csv")

        self.assertIn("Error downloading Kiuwan CSV", str(context.exception))
        self.assertIn("404 Not Found", str(context.exception))