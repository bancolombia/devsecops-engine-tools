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
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


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

        self._write_function_scan_report(function_scan)
        return function_scan

    def _write_function_scan_report(self, function_scan):
        try:
            report = self._build_scan_report(function_scan)
            if report is None:
                return

            self._sanitize_vulnerability_dates(report)
            result_file_name = self._resolve_result_file_name(report)
            with open(result_file_name, "w", encoding="utf-8") as fp:
                json.dump(report, fp)
            if isinstance(self.dict_args, dict):
                self.dict_args["path_file_results"] = os.path.abspath(result_file_name)

        except Exception as exc:
            logger.error("Error generating function scan report file: %s", exc)

    def _build_scan_report(self, function_scan):
        if isinstance(function_scan, dict):
            if "results" in function_scan:
                return function_scan
            return {"results": [function_scan]}
        if isinstance(function_scan, list):
            return {"results": function_scan}
        return None

    def _sanitize_vulnerability_dates(self, report):
        for result in report.get("results", []):
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

    def _resolve_result_file_name(self, report):
        results_list = report.get("results", [])
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
        return f"{safe_name}_function_scan_result.json"

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
        name_match = re.search(r"Scan results for: function (.+?)\s", stdout)
        function_name = name_match.group(1) if name_match else "unknown.zip"

        return {
            "results": [
                {
                    "name": function_name,
                    "complianceDistribution": self._extract_distribution(
                        stdout,
                        r"Compliance found for function .*?: total - (\d+), critical - (\d+), high - (\d+), medium - (\d+), low - (\d+)"
                    ),
                    "complianceScanPassed": "Compliance threshold check results: PASS" in stdout,
                    "vulnerabilities": self._extract_vulnerability_table(stdout),
                    "vulnerabilityDistribution": self._extract_distribution(
                        stdout,
                        r"Vulnerabilities found for function .*?: total - (\d+), critical - (\d+), high - (\d+), medium - (\d+), low - (\d+)"
                    ),
                    "vulnerabilityScanPassed": "Vulnerability threshold check results: PASS" in stdout
                }
            ]
        }

    def _extract_distribution(self, stdout: str, pattern: str) -> dict:
        match = re.search(pattern, stdout)
        if not match:
            return {}
        return {
            "critical": int(match.group(2)),
            "high": int(match.group(3)),
            "medium": int(match.group(4)),
            "low": int(match.group(5)),
            "total": int(match.group(1))
        }

    def _clean_scan_text(self, text) -> str:
        cleaned_text = ANSI_ESCAPE_RE.sub("", str(text))
        return cleaned_text.strip()

    def _extract_vulnerability_rows(self, stdout: str) -> list:
        lines = stdout.splitlines()
        table_start = [i for i, line in enumerate(lines) if 'CVE-' in line]
        table_data = []
        if not table_start:
            return table_data

        i = table_start[0]
        while i < len(lines):
            if "CVE-" not in lines[i]:
                i += 1
                continue
            row = lines[i]
            desc_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("| CVE-") and "+---" not in lines[i]:
                desc_lines.append(lines[i])
                i += 1
            table_data.append(row + "\n" + "\n".join(desc_lines))
        return table_data

    def _extract_vulnerability_table(self, stdout: str) -> list:
        vulnerabilities = []
        for row in self._extract_vulnerability_rows(stdout):
            parts = [x.strip() for x in row.split("|")[1:-1]]
            if len(parts) >= 9:
                vulnerabilities.append(self._build_vulnerability_entry(parts))
        return vulnerabilities

    def _build_vulnerability_entry(self, parts) -> dict:
        return {
            "id": self._clean_scan_text(parts[0]),
            "severity": self._clean_scan_text(parts[1]),
            "cvss": float(self._clean_scan_text(parts[2])) if parts[2] else 0.0,
            "packageName": self._clean_scan_text(parts[3]),
            "packageVersion": self._clean_scan_text(parts[4]),
            "status": self._clean_scan_text(parts[5]),
            "publishedDate": self._clean_scan_text(parts[6]),
            "discoveredDate": self._clean_scan_text(parts[7]),
            "description": self._clean_scan_text(parts[8]).replace("u00a0", " ").strip(" .") + "..."
        }
