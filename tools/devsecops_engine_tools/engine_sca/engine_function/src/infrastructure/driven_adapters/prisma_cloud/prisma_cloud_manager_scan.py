import os
import glob
import subprocess
import re
import json
from devsecops_engine_tools.engine_sca.engine_function.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils import download_twistcli



logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class PrismaCloudManagerScan:
    def __init__(
        self,
        tool_run: ToolGateway,
        dict_args
    ):
        self.tool_run = tool_run
        self.dict_args = dict_args

    def run_tool_function_sca(
        self, 
        remoteconfig, 
        secret_tool,
        token_engine_container,
    ):
        prisma_key = (
            f"{secret_tool['access_prisma']}:{secret_tool['token_prisma']}" if secret_tool else token_engine_container
        )
        file_path = os.path.join(
            os.getcwd(), remoteconfig["PRISMA_CLOUD"]["TWISTCLI_PATH"]
        )
        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                prisma_key,
                remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
            )
        folder_path = self.dict_args["folder_path"]
        function_scan = self._scan_function(
            file_path,
            folder_path,
            remoteconfig,
            prisma_key,
        )
        if not function_scan:
            return function_scan

        try:
            if isinstance(function_scan, dict):
                if "results" in function_scan:
                    report = function_scan
                else:
                    report = {"results": [function_scan]}
            elif isinstance(function_scan, list):
                report = {"results": function_scan}
            else:
                return function_scan
            results_list = report.get("results", [])
            for result in results_list:
                if not isinstance(result, dict):
                    continue
                vulns = result.get("vulnerabilities", []) or []
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    for field in ("publishedDate", "discoveredDate", "fixDate"):
                        val = v.get(field)
                        if not isinstance(val, str):
                            continue
                        if any(token in val for token in ("days", "months", "month", ">", "ago")):
                            v.pop(field, None)
                            continue

            function_name = "function"
            if results_list:
                first_result = results_list[0]
                if isinstance(first_result, dict):
                    function_name = first_result.get("name", function_name)

            safe_name = (
                function_name.replace("/", "_")
                .replace(" ", "_")
                .replace(":", "_")
                .replace(".", "_")
            )
            result_file_name = f"{safe_name}_function_scan_result.json"
            with open(result_file_name, "w", encoding="utf-8") as fp:
                json.dump(report, fp)
            if isinstance(self.dict_args, dict):
                self.dict_args["path_file_results"] = os.path.abspath(result_file_name)

        except Exception as exc:
            logger.error("Error generating function scan report file: %s", exc)
        return function_scan

    def _split_prisma_token(self, prisma_key):
        try:
            access_prisma, token_prisma = prisma_key.split(":")
            return access_prisma, token_prisma
        except ValueError:
            raise ValueError("The string is not properly formatted. Make sure it contains a ':'.")

    def _scan_function(self, file_path, folder_path, remoteconfig, prisma_key):
        function_path = glob.glob(os.path.join(folder_path, "*.zip"))
        if not function_path:
            print("No .zip file found [Scanning skipped]")
            return None
        zip_name = os.path.basename(function_path[0])
        command = (
            file_path,
            "serverless",
            "scan",
            "--address",
            remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            "--user",
            self._split_prisma_token(prisma_key)[0],
            "--password",
            self._split_prisma_token(prisma_key)[1],
            "--details",
            function_path[0],
        )
        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace"
            )
            print(f"The function {zip_name} was scanned")
            result = self._parse_scan_results(result.stdout)
            return result

        except subprocess.CalledProcessError as e:
            logger.error(
                f"Error during function scan of {zip_name}"
                f"\n errorcode: {e.returncode}"
                f"\n output: {e.output}"
            )
    def download_twistcli(self, file_path, prisma_key, prisma_console_url, prisma_api_version) -> int:
        """
        Método de instancia separado (lo que usan los tests),
        delega en el util compat 'basic' para no romper aserciones.
        """
        return download_twistcli(file_path, prisma_key, prisma_console_url, prisma_api_version)

    def _parse_scan_results(self, stdout: str) -> dict:
        def extract_dist(pattern: str) -> dict:
            match = re.search(pattern, stdout)
            return {
                "critical": int(match.group(2)),
                "high": int(match.group(3)),
                "medium": int(match.group(4)),
                "low": int(match.group(5)),
                "total": int(match.group(1))
            } if match else {}

        def clean_text(text) -> str:
            cleaned_text = text.replace('\x1b[0m', '')
            cleaned_text = cleaned_text.replace('\x1b[91;1m', '')
            cleaned_text = cleaned_text.replace('\x1b[33;1m','')
            return cleaned_text

        def extract_table() -> list:
            lines = stdout.splitlines()
            table_start = [i for i, line in enumerate(lines) if 'CVE-' in line]
            table_data = []
            if table_start:
                i = table_start[0]
                while i < len(lines):
                    if "CVE-" in lines[i]:
                        row = lines[i]
                        desc_lines = []
                        i += 1
                        while i < len(lines) and not lines[i].strip().startswith("| CVE-") and not "+---" in lines[i]:
                            desc_lines.append(lines[i])
                            i += 1
                        full_row = row + "\n" + "\n".join(desc_lines)
                        table_data.append(full_row)
                    else:
                        i += 1

            vulnerabilities = []
            for row in table_data:
                parts = [x.strip() for x in row.split("|")[1:-1]]
                if len(parts) >= 9:
                    vuln = {
                        "id": clean_text(parts[0]),
                        "severity": clean_text(parts[1]),
                        "cvss": float(clean_text(parts[2])) if parts[2] else 0.0,
                        "packageName": clean_text(parts[3]),
                        "packageVersion": clean_text(parts[4]),
                        "status": clean_text(parts[5]),
                        "publishedDate": clean_text(parts[6]),
                        "discoveredDate": clean_text(parts[7]),
                        "description": clean_text(parts[8]).replace("u00a0", " ").strip(" .") + "..."
                    }
                    vulnerabilities.append(vuln)
            return vulnerabilities

        name_match = re.search(r"Scan results for: function (.+?)\s", stdout)
        function_name = name_match.group(1) if name_match else "unknown.zip"

        return {
            "results": [
                {
                    "name": function_name,
                    "complianceDistribution": extract_dist(r"Compliance found for function .*?: total - (\d+), critical - (\d+), high - (\d+), medium - (\d+), low - (\d+)"),
                    "complianceScanPassed": "Compliance threshold check results: PASS" in stdout,
                    "vulnerabilities": extract_table(),
                    "vulnerabilityDistribution": extract_dist(r"Vulnerabilities found for function .*?: total - (\d+), critical - (\d+), high - (\d+), medium - (\d+), low - (\d+)"),
                    "vulnerabilityScanPassed": "Vulnerability threshold check results: PASS" in stdout
                }
            ]
        }
