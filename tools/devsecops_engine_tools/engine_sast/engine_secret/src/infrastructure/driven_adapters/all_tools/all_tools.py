from concurrent.futures import ThreadPoolExecutor, as_completed
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_tool import (
    GitleaksTool,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import (
    TrufflehogRun,
)
import json
import os

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class AllToolsSecretScan(ToolGateway):
    gitleaks_tool: GitleaksTool = GitleaksTool()
    trufflehog_tool: TrufflehogRun = TrufflehogRun()
    
    def install_tool(self, agent_os, agent_temp_dir, tool_version) -> any:
        """Install both tools in parallel"""
        gitleaks_version = tool_version.get("GITLEAKS")
        trufflehog_version = tool_version.get("TRUFFLEHOG")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.gitleaks_tool.install_tool, agent_os, agent_temp_dir, gitleaks_version),
                executor.submit(self.trufflehog_tool.install_tool, agent_os, agent_temp_dir, trufflehog_version)
            ]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error installing tool: {str(e)}")

    def run_tool_secret_scan(
        self, 
        files, 
        agent_os, 
        agent_work_folder, 
        repository_name, 
        config_tool, 
        secret_tool, 
        secret_external_checks, 
        agent_temp_dir, 
        tool, 
        folder_path
        ):
        """Run both secret scanning tools in parallel and collect their results."""
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Start both scans
            future_gitleaks = executor.submit(
                self.gitleaks_tool.run_tool_secret_scan,
                files, agent_os, agent_work_folder, repository_name, 
                config_tool, secret_tool, secret_external_checks, 
                agent_temp_dir, "gitleaks", folder_path
            )
            future_trufflehog = executor.submit(
                self.trufflehog_tool.run_tool_secret_scan,
                files, agent_os, agent_work_folder, repository_name, 
                config_tool, secret_tool, secret_external_checks, 
                agent_temp_dir, "trufflehog", folder_path
            )
            
            # Get results
            findings_gitleaks, finding_path_gitleaks = future_gitleaks.result()
            findings_trufflehog, finding_path_trufflehog = future_trufflehog.result()
        
        # Deduplicate: Remove TruffleHog findings that match Gitleaks findings
        try:
            # Build normalized set from Gitleaks
            gitleaks_normalized = set()
            for g in findings_gitleaks or []:
                norm = self._normalize_for_cross_tool_dedup(g, is_gitleaks=True)
                if norm:
                    gitleaks_normalized.add(norm)

            # Deduplicate within TruffleHog
            trufflehog_after_internal_dedup = self._deduplicate_trufflehog_internal(findings_trufflehog or [])
            
            # Filter TruffleHog against Gitleaks
            filtered_trufflehog = []
            for idx, t in enumerate(trufflehog_after_internal_dedup):
                norm = self._normalize_for_cross_tool_dedup(t, is_gitleaks=False)

                if norm and norm in gitleaks_normalized:
                    continue
                else:
                    filtered_trufflehog.append(t)

            findings = [{"gitleaks": findings_gitleaks, "trufflehog": filtered_trufflehog}]
            
            # Rewrite the TruffleHog findings file with only deduplicated results
            self._rewrite_trufflehog_file(filtered_trufflehog, finding_path_trufflehog)
            
        except Exception as e:
            logger.error(f"Error during deduplication: {e}")
            findings = [{"gitleaks": findings_gitleaks, "trufflehog": findings_trufflehog}]

        finding_path = finding_path_gitleaks + "#" + finding_path_trufflehog
        return findings, finding_path

    def _deduplicate_trufflehog_internal(self, findings: list) -> list:
        """Deduplicate within TruffleHog: remove findings with same filename+line+secret but different detectors."""
        if not findings:
            return findings
        
        # Use filename+line+secret as key
        seen_by_file_line_secret = {}
        deduplicated = []
        
        for finding in findings:
            path = ""
            try:
                path = (
                    finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "")
                )
            except (AttributeError, TypeError):
                path = finding.get("file", "") or ""
            
            # Extract only filename
            filename = path.split('/')[-1] if '/' in path else path
            filename = filename.split('\\')[-1] if '\\' in filename else filename
            
            # Extract line number
            try:
                line = (
                    finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("line", "")
                )
            except (AttributeError, TypeError):
                line = finding.get("line") or ""
            
            # Get the secret
            secret = finding.get("Raw") or finding.get("RawV2") or finding.get("Match") or finding.get("Redacted") or ""
            masked_secret = self._mask_secret(secret)
            
            # Key: filename + line + secret
            key = f"{filename}|{line}|{masked_secret}"
            
            if key not in seen_by_file_line_secret:
                seen_by_file_line_secret[key] = True
                deduplicated.append(finding)
        
        return deduplicated

    def _normalize_for_cross_tool_dedup(self, item: dict, is_gitleaks: bool = True, include_line: bool = True) -> str:
        """
        Normalize item for cross-tool deduplication (Gitleaks vs TruffleHog).
        """
        if not item:
            return ""

        path = self._extract_dedup_path(item, is_gitleaks)
        filename = self._extract_dedup_filename(path)
        line = self._extract_dedup_line(item, is_gitleaks) if include_line else ""
        secret = self._extract_dedup_secret(item, is_gitleaks)
        masked = self._mask_secret(secret)

        # Build normalized key
        if not (filename or masked):
            return ""

        if include_line:
            # Strict: filename|line|secret
            normalized = f"{filename}|{line}|{masked}"
        else:
            # Fallback: filename|secret (no line)
            normalized = f"{filename}|{masked}"

        return normalized.strip()

    def _extract_dedup_path(self, item: dict, is_gitleaks: bool) -> str:
        if is_gitleaks:
            return item.get("File", "") or ""
        # TruffleHog nested path extraction
        try:
            return (
                item.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file", "")
            )
        except (AttributeError, TypeError):
            return item.get("file", "") or ""

    def _extract_dedup_filename(self, path: str) -> str:
        # Extract only filename from path
        filename = path.split('/')[-1] if '/' in path else path
        return filename.split('\\')[-1] if '\\' in filename else filename

    def _extract_dedup_line(self, item: dict, is_gitleaks: bool):
        if is_gitleaks:
            return item.get("StartLine") or item.get("line") or ""
        try:
            return (
                item.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("line", "")
            )
        except (AttributeError, TypeError):
            return item.get("line") or ""

    def _extract_dedup_secret(self, item: dict, is_gitleaks: bool):
        if is_gitleaks:
            return item.get("Secret") or item.get("Match") or ""
        return item.get("Raw") or item.get("RawV2") or item.get("Match") or item.get("Redacted") or ""

    def _rewrite_trufflehog_file(self, filtered_findings: list, file_path: str) -> None:
        """Rewrite the TruffleHog findings file with deduplicated results."""
        try:
            
            if not file_path or not os.path.exists(file_path):
                return
            
            with open(file_path, "w") as file:
                file.writelines(json.dumps(finding) + '\n' for finding in filtered_findings)
                
        except Exception as e:
            logger.error(f"Error rewriting TruffleHog file: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _mask_secret(self, secret: str) -> str:
        """Mask secret value for comparison: keep first 3 and last 3 chars"""
        if not secret:
            return ""
        secret = str(secret)
        if "*" in secret:
            return secret
        if len(secret) > 6:
            return secret[:3] + "*" * 9 + secret[-3:]
        return secret
