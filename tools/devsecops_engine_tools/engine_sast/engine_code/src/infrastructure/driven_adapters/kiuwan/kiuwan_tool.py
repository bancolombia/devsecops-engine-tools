import os
from pathlib import Path
import subprocess
import platform
import time
import fnmatch
import urllib.request
import zipfile
import stat
import shutil
from typing import Dict, Any, List, Optional, Union, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.config_tool import ConfigTool
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_core.src.domain.model.finding import EngineCodeFinding
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.kiuwan.kiuwan_deserealizator import KiuwanDeserealizator

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class KiuwanTool(ToolGateway):
    
    """
        Kiuwan class to make analysis. This class install kiuwan CLI in different OS(Linux/MacOs/Windows).
        This class make an analysis and promote to baseline if the specified requirements are supply.
    """

    def __init__(self, config: Dict[str, Any]):
        self.user: str = config.get("user_engine_code", "")
        self.password: str = config.get("token_engine_code", "")
        self.base_url: str = config.get("host_engine_code", "")
        self.build_execution_id = config.get("build_execution_id", "")
        self.source_branch_name: str = config.get("source_branch_name", "")
        self.target_branch: str = config.get("target_branch", "")
        self.build_task: str = config.get("build_task", "")
        self.modelo_regla: dict = config.get("MODELOS", {}).get(self.build_task, "General")
        self.domain_id: str = config.get("domain_id_engine_code", "")
        self.headers = {"X-KW-CORPORATE-DOMAIN-ID": self.domain_id}
        self.working_directory: str = os.getcwd()
        self.kiuwan_agent_path: Optional[str] = self._find_or_download_kiuwan_agent()
        self.repository_name: str = ""        

        
    def run_tool(
        self,
        folder_to_scan: str,
        pull_request_files: List[str],
        agent_work_folder: str,
        repository: str,
        config_tool: ConfigTool
    ) -> Tuple[List[Any], Optional[str]]:
        """
        Run the code scan tool.
        """
        # Validar target branch
        if not self._validate_target_branch(config_tool):
            logger.warning("Target branch %s is not allowed for analysis", self.target_branch)
            return [], None
        
        # Configurar el repositorio desde el parámetro
        self.repository_name = repository
        
        # Preparar el directorio de escaneo
        scan_directory = self._prepare_scan_directory(
            folder_to_scan, 
            pull_request_files, 
            agent_work_folder, 
            config_tool
        )
        
        logger.info(
            """== Context: ==
        - Repository: %s
        - Source branch: %s
        - Target branch: %s
        - Scan directory: %s
        == == == ==""",
            self.repository_name,
            self.source_branch_name,
            self.target_branch,
            scan_directory
        )
        
        analysis_type = self._determine_analysis_type()
        logger.info("Analysis selected: %s\n", analysis_type)
        logger.info("Analysis %s started", analysis_type)
        
        self._execute_kiuwan_scan(analysis_type, scan_directory)
        self._validate_results(analysis_type)
        last_analysis = self._fetch_last_analysis()
        self._promote_to_baseline(last_analysis)
        if not last_analysis:
            last_analysis = self._fetch_last_analysis()
        defects = self._fetch_defects_for_analysis(last_analysis.get("analysisCode", ""))
        findings= self._map_defects_to_findings(last_analysis, defects, last_analysis.get("analysisCode", ""), config_tool.data["KIUWAN"]["SEVERITY"])

        defects_file_path = self._download_kiuwan_csv_official(last_analysis.get("analysisCode", ""), "kiuwan_findings.csv")

        return findings, defects_file_path

    def _validate_target_branch(self, config_tool: ConfigTool) -> bool:
        """Validate if the target branch is allowed for analysis."""
        target_branches = config_tool.target_branches
        if target_branches and self.target_branch not in target_branches:
            return False
        return True

    def _prepare_scan_directory(
        self, 
        folder_to_scan: str, 
        pull_request_files: List[str], 
        agent_work_folder: str, 
        config_tool: ConfigTool
    ) -> str:
        """Prepare the directory that will be scanned by Kiuwan."""
        
        # Crear directorio temporal para el escaneo
        temp_scan_dir = os.path.join(agent_work_folder, "temp_folder_to_scan")
        os.makedirs(temp_scan_dir, exist_ok=True)
        
        if folder_to_scan is None:
            # Copiar solo los archivos del PR
            logger.info("Copying PR files to temporary scan directory")
            for file_path in pull_request_files:
                if os.path.exists(file_path):
                    # Mantener la estructura de directorios
                    relative_path = os.path.relpath(file_path, self.working_directory)
                    dest_path = os.path.join(temp_scan_dir, relative_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy2(file_path, dest_path)
        else:
            # Copiar todo el folder_to_scan
            logger.info("Copying folder_to_scan to temporary scan directory")
            if os.path.exists(folder_to_scan):
                shutil.copytree(folder_to_scan, temp_scan_dir, dirs_exist_ok=True)
        
        # Manejar exclusiones
        if config_tool.exclude_folder:
            self._handle_exclusions(temp_scan_dir, config_tool.exclude_folder, agent_work_folder)
        
        return temp_scan_dir

    def _handle_exclusions(self, scan_dir: str, exclude_folders: List[str], agent_work_folder: str):
        """Move excluded files/folders to a separate directory."""
        
        exclude_dir = os.path.join(agent_work_folder, "exclude_to_scan")
        os.makedirs(exclude_dir, exist_ok=True)
        
        logger.info("Processing exclusions: %s", exclude_folders)
        
        for exclude_pattern in exclude_folders:
            # Buscar archivos/carpetas que coincidan con el patrón
            for root, dirs, files in os.walk(scan_dir):
                self._exclude_matching_dirs(root, dirs, exclude_pattern, scan_dir, exclude_dir)
                self._exclude_matching_files(root, files, exclude_pattern, scan_dir, exclude_dir)

    def _exclude_matching_dirs(self, root, dirs, exclude_pattern, scan_dir, exclude_dir):
        for dir_name in dirs[:]:  # Usar slice copy para modificar durante iteración
            if self._matches_exclude_pattern(dir_name, exclude_pattern):
                self._move_to_exclude_dir(root, dir_name, scan_dir, exclude_dir, "directory")
                dirs.remove(dir_name)  # No procesar este directorio más

    def _exclude_matching_files(self, root, files, exclude_pattern, scan_dir, exclude_dir):
        for file_name in files[:]:
            if self._matches_exclude_pattern(file_name, exclude_pattern):
                self._move_to_exclude_dir(root, file_name, scan_dir, exclude_dir, "file")

    def _move_to_exclude_dir(self, root, item_name, scan_dir, exclude_dir, item_kind):
        source_path = os.path.join(root, item_name)
        relative_path = os.path.relpath(source_path, scan_dir)
        dest_path = os.path.join(exclude_dir, relative_path)

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.move(source_path, dest_path)
        logger.info("Excluded %s: %s", item_kind, relative_path)

    def _matches_exclude_pattern(self, item_name: str, pattern: str) -> bool:
        """Check if an item matches the exclusion pattern."""
        return fnmatch.fnmatch(item_name, pattern) or pattern in item_name

    def _determine_analysis_type(self) -> str:
        """Determine if baseline or delivery analysis is needed."""
        url = f"{self.base_url}/applications/list?applicationName={self.repository_name}"
        try:
            response = requests.get(url, headers=self.headers, auth=(self.user, self.password), timeout=60)
            response.raise_for_status()
            apps = response.json()
            app_names = [app["name"] for app in apps]
            return "baseline" if self.repository_name not in app_names else "delivery"
        except (requests.RequestException, ValueError) as e:
            raise RuntimeError(f"Failed to determine analysis type in engine code: {e}") from e

    def _execute_kiuwan_scan(self, analysis_type: str, scan_directory: str) -> Union[subprocess.CompletedProcess, Dict[str, Any]]:
        """Execute Kiuwan baseline or delivery analysis."""
    
        cmd = [
            self.kiuwan_agent_path,
            "--user", self.user,
            "--pass", self.password,
            "--domain-id", self.domain_id,
            "--softwareName", self.repository_name,
            "--sourcePath", scan_directory,  # Usar el directorio preparado
            "--label", self.build_execution_id,
            "--wait-for-results",
            "--model-name", self.modelo_regla
        ]
        
        if analysis_type == "baseline":
            cmd.extend(["--create", "--analysis-scope", "baseline"])
        else:
            cmd.extend(["--analysis-scope", "completeDelivery", "--change-request", "inprogress",
                        "--branch-name", self.source_branch_name])
        
        logger.info("Kiuwan analysis will be executed using model %s", self.modelo_regla)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, errors="ignore")
            logger.info("Scan results: %s", result)
            return result
        except subprocess.CalledProcessError as e:
            error = {"status": "failed", "output": e.stderr}
            logger.error("Scan results: %s", error)
            return error

    def _validate_results(self, analysis_type: str):

        """Validate analysis results."""
        try:
            if analysis_type == "baseline":
                logger.info("Validate Baseline Results with applicationBusinessValue")
                url = f"{self.base_url}/applications/list?applicationName={self.repository_name}"
                response = requests.get(url, headers=self.headers, auth=(self.user, self.password), timeout=60)
                response.raise_for_status()
                application_business_value = response.json()[0].get("applicationBusinessValue")
                if application_business_value in ["CRITICAL", "HIGH"]:
                    logger.warning("Baseline analysis failed: Business Value is %s", application_business_value)
            else:
                logger.info("Validate Delivery Results with AuditResult")
                url = f"{self.base_url}/applications/deliveries?application={self.repository_name}"
                response = requests.get(url, headers=self.headers, auth=(self.user, self.password), timeout=60)
                response.raise_for_status()
                results = response.json()

                for result in results:
                    audit_result = result.get("auditResult", "")
                    if audit_result != "OK":
                        logger.warning("Delivery analysis failed: Audit Result is %s", audit_result)
                
        except (subprocess.CalledProcessError, ValueError) as e:
            logger.error("Analysis result failed:\nRepository: %s", self.repository_name)
            raise RuntimeError(f"Validation analysis results failed: {e}") from e

    def _fetch_last_analysis(self) -> Dict[str, Any]:
        """
        Fetch the last analysis for the repository and wait until it is finished.

        Returns:
            Dictionary containing the last analysis data.

        Raises:
            RuntimeError: If there's an error fetching the analysis or if the response is invalid.
        """
        last_analysis_url = f"{self.base_url}/applications/last_analysis?application={self.repository_name}"
        logger.info("Getting last analysis...")
        max_tries = 10
        tried = 0
        try:
            while tried <= max_tries:
                response = requests.get(
                    last_analysis_url,
                    headers=self.headers,
                    auth=(self.user, self.password),
                    timeout=60,
                )
                response.raise_for_status()
                last_analysis = response.json()
                
                if last_analysis.get("analysisStatus") == "FINISHED":
                    return last_analysis
                
                logger.info("Analysis status %s, waiting status FINISHED", last_analysis.get('analysisStatus'))
                time.sleep(5)
                tried += 1
            return None
        except (requests.RequestException, ValueError) as e:
            raise RuntimeError(f"Failed to fetch last analysis: {e}") from e

    def _promote_to_baseline(self, last_analysis):

        """Promote delivery to baseline if on master branch."""
        
        if self.target_branch == "master" or not last_analysis:
            logger.info("Promoting delivery to baseline...")
            cmd = [
                self.kiuwan_agent_path,
                "--promote-to-baseline",
                "--user", self.user,
                "--pass", self.password,
                "--domain-id", self.domain_id,
                "--softwareName", self.repository_name,
                "--change-request", "inprogress",
                "--label", self.build_execution_id,
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=True, errors="ignore")
                logger.info("Promotion completed")
            except subprocess.CalledProcessError as e:
                logger.error("Promotion failed: %s", e)

        else:
            logger.info("No promotion needed")


    def _fetch_defects_for_analysis(self, analysis_code: str) -> Dict[str, Any]:
        """
        Fetch all defects for a given analysis code, handling pagination.

        Args:
            analysis_code: The code of the analysis to fetch defects for.

        Returns:
            Dictionary containing all defects and metadata.

        Raises:
            RuntimeError: If there's an error fetching defects or if the response is invalid.
        """
        base_defects_url = f"{self.base_url}/apps/analysis/{analysis_code}/defects"
        first_defects_page = "?page=1&count=5000"
        last_analysis_defects_url = base_defects_url + first_defects_page
        
        logger.info("Getting defects...")
        try:
            response = requests.get(
                last_analysis_defects_url,
                headers=self.headers,
                auth=(self.user, self.password),
                timeout=60,
            )
            response.raise_for_status()
            last_analysis_defects: Dict[str, Any] = response.json()

            all_defects = last_analysis_defects.get("defects", [])
            total_defects = last_analysis_defects.get("defects_count", 0)

            if total_defects > 5000:
                total_pages = (total_defects + 4999) // 5000
                for page in range(2, total_pages + 1):
                    paginated_url = f"{base_defects_url}?page={page}&count=5000"
                    logger.info("Fetching page %s of defects...", page)
                    response = requests.get(
                        paginated_url,
                        headers=self.headers,
                        auth=(self.user, self.password),
                        timeout=60,
                    )
                    if response.status_code == 200:
                        page_data = response.json()
                        all_defects.extend(page_data.get("defects", []))
                    else:
                        logger.warning("Failed to fetch page %s: %s", page, response.status_code)

            last_analysis_defects["defects"] = all_defects
            return last_analysis_defects
        
        except (requests.RequestException, ValueError) as e:
            raise RuntimeError(f"Failed to fetch defects: {e}") from e

    def _download_kiuwan_csv_official(self, analysis_code: str, output_path: str = "kiuwan_findings.csv") -> str:
        """
        Download the official Kiuwan SAST CSV report using the vulnerabilities/export API.
        Compatible with DefectDojo's 'Kiuwan Scan' parser.

        Args:
            analysis_code (str): The analysis code to export.
            output_path (str): Path to save the CSV file.

        Returns:
            str: Path to the downloaded CSV file.
        """
        csv_url = (
            f"{self.base_url}/applications/analysis/vulnerabilities/export?"
            f"application={self.repository_name}&code={analysis_code}&type=CSV"
        )

        try:
            logger.info("Downloading official Kiuwan CSV from: %s", csv_url)
            response = requests.get(
                csv_url,
                auth=(self.user, self.password),
                headers=self.headers,
                timeout=60,
                stream=True
            )
            response.raise_for_status()

            if 'text/csv' not in response.headers.get('Content-Type', ''):
                logger.warning("Response Content-Type is not CSV: %s", response.headers.get('Content-Type'))

            with open(output_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            logger.info("Official Kiuwan CSV downloaded successfully: %s", output_path)
            return output_path

        except RequestException as e:
            logger.error("Failed to download Kiuwan CSV: %s", e)
            raise RuntimeError(f"Error downloading Kiuwan CSV from {csv_url}: {e}") from e
    
    def _map_defects_to_findings(
        self,
        last_analysis: Dict[str, Any],
        defects_data: Dict[str, Any],
        analysis_code: str,
        severity_mapper: Dict[str,str]
    ) -> List[EngineCodeFinding]:
        return KiuwanDeserealizator.get_findings(last_analysis, defects_data, analysis_code, severity_mapper)

    def _find_or_download_kiuwan_agent(self) -> str:
        """Ensure Kiuwan agent is available and return its path."""

        system = platform.system()
        agent_script = {
            "Windows": "agent.cmd",
            "Linux": "agent.sh",
            "Darwin": "agent.sh"  # macOS
        }.get(system)

        if not agent_script:
            raise RuntimeError(f"Unsupported OS: {system}")

        agent_path = self._search_agent_script(agent_script)
        if agent_path:
            return agent_path

        self._download_and_extract_kiuwan()
        agent_path = self._search_agent_script(agent_script)

        if not agent_path:
            raise FileNotFoundError(f"{agent_script} was not found.")

        logger.info("Kiuwan agent path is: %s", agent_path)
        return agent_path

    def _search_agent_script(self, script_name: str) -> str:
        """Search for the Kiuwan script in the tools directory."""
        for root, _, files in os.walk(self.working_directory):
            if script_name in files:
                return os.path.join(root, script_name)
        return ""

    def _set_execution_permissions(self, extracted_files):

        """Set execution permissions to extracted files"""

        # Set execution permissions on .sh files if on Unix-like system
        if platform.system().lower() in ["linux", "darwin"]:
            for file_path in extracted_files:
                if file_path.endswith(".sh"):
                    try:
                        os.chmod(file_path, os.stat(file_path).st_mode | stat.S_IEXEC)
                        logger.info("Execution permissions granted to: %s", file_path)
                    except Exception as e:
                        logger.warning("Failed to set execution permissions for %s : %s", file_path, e)

    def _download_and_extract_kiuwan(self):
        """Download and extract the Kiuwan CLI, flattening the internal folder structure and setting execution permissions."""
        kiuwan_url = "https://www.kiuwan.com/pub/analyzer/KiuwanLocalAnalyzer.zip"
        zip_path = os.path.join(self.working_directory, "KiuwanLocalAnalyzer.zip")

        try:

            parsed_url = urlparse(kiuwan_url)
            if parsed_url.scheme != "https":
                raise ValueError("Only HTTPS URLs are allowed for downloading Kiuwan CLI.")

            logger.info("Downloading Kiuwan CLI...")
            urllib.request.urlretrieve(kiuwan_url, zip_path) # nosec

            extracted_files = self._extract_zip(zip_path)

            os.remove(zip_path)
            logger.info("Kiuwan CLI extracted successfully into the root tools directory.")
            
            self._set_execution_permissions(extracted_files)

        except Exception as e:
            raise RuntimeError(f"Error downloading or extracting the Kiuwan agent: {e}") from e

    def _extract_zip(self, zip_path) -> list:

        """Extract zip files"""

        extracted_files = []

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if member.startswith("KiuwanLocalAnalyzer/") and not member.endswith("/"):
                    relative_path = os.path.relpath(member, "KiuwanLocalAnalyzer")
                    target_path = os.path.join(self.working_directory, relative_path)
                    
                    Path(os.path.dirname(target_path)).mkdir(parents=True, exist_ok=True)
                    with zip_ref.open(member) as source, open(target_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                    extracted_files.append(target_path)
        
        return extracted_files
    

def get_kiuwan_instance(dict_args: Dict, devops_platform_gateway) -> KiuwanTool:
    """
    Create a kiuwan instance to scan
    """
    logger.info("Retrieving kiuwan configuration file...")
    kiuwan_config_tool = devops_platform_gateway.get_remote_config(
        dict_args["remote_config_repo"], 
        "/engine_sast/engine_code/ConfigTool.json",
        dict_args["remote_config_branch"]
    )
    logger.info("Kiuwan configuration file retrieved")
    logger.info("Settings config dictionary to scan tool...")
    config = {
        "host_engine_code": kiuwan_config_tool["KIUWAN"]["SERVER"]["BASE_URL"],
        "user_engine_code": kiuwan_config_tool["KIUWAN"]["SERVER"]["USER"],
        "domain_id_engine_code": kiuwan_config_tool["KIUWAN"]["SERVER"]["DOMAIN_ID"],
        "token_engine_code": dict_args["token_engine_code"],
        "build_execution_id": devops_platform_gateway.get_variable("build_execution_id"),
        "source_branch_name": devops_platform_gateway.get_variable("branch_name"),
        "target_branch": devops_platform_gateway.get_variable("target_branch"),
        "build_task": devops_platform_gateway.get_variable("build_task"),
        "MODELOS": kiuwan_config_tool["KIUWAN"]["MODELOS"]
    }
    return KiuwanTool(config)