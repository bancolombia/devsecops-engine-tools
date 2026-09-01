from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.secrets_manager_gateway import (
    SecretsManagerGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
import shutil

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class Copacetic:
    def __init__(
        self,
        vulnerability_management_gateway: VulnerabilityManagementGateway,
        secrets_manager_gateway: SecretsManagerGateway,
        devops_platform_gateway: DevopsPlatformGateway,
        remote_config_source_gateway: DevopsPlatformGateway,
        copacetic_gateway,
    ):
        self.vulnerability_management_gateway = vulnerability_management_gateway
        self.secrets_manager_gateway = secrets_manager_gateway
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.copacetic_gateway = copacetic_gateway

    def process(self, args):
        try:
            copacetic_config = self.remote_config_source_gateway.get_remote_config(
                args["remote_config_repo"], "/engine_integrations/copacetic/ConfigTool.json", args["remote_config_branch"]
            )

            image = args.get("image")
            vulnerability_report = args.get("vulnerability_report")
            patch_format = args.get("patch_format", "trivy")
            
            if not image:
                raise ValueError("Image is required for Copacetic patching")

            logger.info(f"Starting Copacetic patching for image: {image}")

            image_info = {}
            if hasattr(self.copacetic_gateway, 'get_image_info'):
                image_info = self.copacetic_gateway.get_image_info(image)
                if not image_info.get("exists", False):
                    logger.info(f"Image {image} may not exist locally. Copacetic will attempt to pull it.")

            patch_result = self.copacetic_gateway.patch_image(
                image=image,
                vulnerability_report=vulnerability_report,
                output_image=args.get("output_image"),
                patch_format=patch_format,
                config=copacetic_config,
                work_folder=self.devops_platform_gateway.get_variable("path_directory"),
                platform=args.get("platform")
            )

            if patch_result["success"]:
                logger.info("Copacetic patching completed successfully")

                if image_info.get("exists", False):
                    patch_result["original_image_info"] = {
                        "architecture": image_info.get("architecture"),
                        "os": image_info.get("os"),
                        "size": image_info.get("size"),
                        "layers": image_info.get("layers")
                    }

                self._print_results_table(patch_result)
            else:
                detailed_error = f"Copacetic patching failed for {image}: {patch_result.get('error', 'Unknown error')}"
                if patch_result.get("copa_error"):
                    detailed_error += f"\nCopa stderr: {patch_result['copa_error']}"
                
                print(
                    self.devops_platform_gateway.message("error", detailed_error)
                )

            return InputCore(
                totalized_exclusions=[],
                threshold_defined=None,
                path_file_results=patch_result.get("output_file", ""),
                custom_message_break_build=f"Copacetic patching completed for {image}",
                scope_pipeline="",
                scope_service="",
                stage_pipeline=self.devops_platform_gateway.get_variable("stage")
            )

        except Exception as e:
            logger.error(f"Error in Copacetic process: {str(e)}")
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Error in Copacetic process: {str(e)}"
                )
            )

    def _print_results_table(self, summary):
        terminal_width = self._get_terminal_width()

        self._print_table_header(terminal_width)
        self._print_image_information(summary)
        vuln_count, vex_generated = self._print_patching_statistics(summary)
        self._print_image_details(summary)
        self._print_patch_details(summary.get('patch_details', []))
        self._print_summary(vuln_count, vex_generated)

        logger.info(f"{'='*terminal_width}\n")

    def _get_terminal_width(self):
        try:
            return min(shutil.get_terminal_size().columns, 100)
        except Exception:
            return 100

    def _print_table_header(self, terminal_width):
        logger.info(f"\n{'='*terminal_width}")
        title = " COPACETIC PATCHING RESULTS "
        padding = (terminal_width - len(title)) // 2
        logger.info(f"{' '*padding}{title}{' '*padding}")
        logger.info(f"{'='*terminal_width}")

    def _print_image_information(self, summary):
        logger.info("\n IMAGE INFORMATION:")
        logger.info(f"   Original Image: {summary['original_image']}")
        logger.info(f"   Patched Image:  {summary['patched_image']}")

    def _print_patching_statistics(self, summary):
        logger.info("\n PATCHING STATISTICS:")
        vuln_count = summary.get('vulnerabilities_patched', 0)
        pkg_count = summary.get('packages_updated', 0)
        vex_generated = summary.get('vex_file_generated', False)

        logger.info(f"   Vulnerabilities Patched: {vuln_count}")
        logger.info(f"   Packages Updated:        {pkg_count}")
        logger.info(f"   VEX Report Generated:    {'Yes' if vex_generated else 'No'}")

        if not vex_generated:
            logger.info("   Note: VEX report not generated (no vulnerability report provided)")

        platforms = summary.get('platforms_processed', [])
        if platforms:
            logger.info(f"   Platforms Processed:     {', '.join(platforms)}")

        return vuln_count, vex_generated

    def _print_image_details(self, summary):
        if not summary.get('original_image_info'):
            return

        info = summary['original_image_info']
        logger.info("\n  IMAGE DETAILS:")
        logger.info(f"   Architecture: {info.get('architecture', 'N/A')}")
        logger.info(f"   OS:           {info.get('os', 'N/A')}")
        logger.info(f"   Size:         {info.get('size', 'N/A')}")
        logger.info(f"   Layers:       {info.get('layers', 'N/A')}")

    def _print_patch_details(self, patch_details):
        if not patch_details:
            return

        logger.info("\n PATCH DETAILS:")
        for i, detail in enumerate(patch_details, 1):
            if isinstance(detail, dict):
                self._print_patch_detail(i, detail)
            else:
                logger.info(f"   {detail}")

            if i < len(patch_details):
                logger.info("")

    def _print_patch_detail(self, index, detail):
        cve = detail.get('vulnerability', detail.get('id', f'PATCH-{index}'))
        logger.info(f"   {cve}")

        packages = detail.get('packages', [])
        if not packages:
            single_package = detail.get('package', detail.get('component'))
            if single_package:
                packages = [single_package]

        for pkg in packages:
            self._print_patch_package(pkg)

        if not packages:
            logger.info("       No package information available")

    def _print_patch_package(self, pkg):
        if isinstance(pkg, dict):
            pkg_name = pkg.get('name', pkg.get('package', 'Unknown'))
            version = pkg.get('version', pkg.get('fixed_version', ''))
            if version:
                logger.info(f"       {pkg_name} (v{version})")
            else:
                logger.info(f"       {pkg_name}")
        else:
            logger.info(f"       {pkg}")

    def _print_summary(self, vuln_count, vex_generated):
        logger.info("\n SUMMARY:")
        if vuln_count > 0:
            logger.info(f"   Status: SUCCESS - {vuln_count} vulnerabilities were patched")
        elif vex_generated:
            logger.info("   Status: COMPLETED - No vulnerabilities found to patch")
        else:
            logger.info("   Status: COMPLETED - Image patched successfully without vulnerability report")
            logger.info("           Use --vulnerability_report to generate detailed VEX output")
