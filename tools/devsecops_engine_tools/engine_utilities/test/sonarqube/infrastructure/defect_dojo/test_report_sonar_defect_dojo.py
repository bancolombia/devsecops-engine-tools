import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo import DefectDojoAdapter
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest
)


class TestDefectDojoAdapter(unittest.TestCase):

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo.DevopsPlatformGateway"
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo.Connect.cmdb"
    ) 
    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo.DefectDojo.send_import_scan"
    )
    def test_send_report_success(self, mock_send_import_scan, mock_cmdb, mock_devops_gateway):
        # Arrange
        mock_devops_gateway_instance = mock_devops_gateway.return_value
        mock_devops_gateway_instance.get_variable.side_effect = lambda x: f"{x}_value"

        mock_cmdb.return_value = ImportScanRequest()
        mock_response = MagicMock()
        mock_response.url = "http://example.com/path/to/test/12345"
        mock_send_import_scan.return_value = mock_response

        secret_tool = {
            "token_defect_dojo": "defect_dojo_token",
            "token_cmdb": "cmdb_token"
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_CMDB": "http://cmdb.example.com",
                    "REGEX_EXPRESSION_CMDB": ".*",
                    "HOST_DEFECT_DOJO": "http://defectdojo.example.com",
                    "CMDB_MAPPING_PATH": ""
                }
            }
        }

        # Act
        DefectDojoAdapter.send_report(
            "http://config_url",
            "http://scm_uri",
            "production",
            secret_tool,
            config_tool,
            mock_devops_gateway_instance,
            "project_key"
        )

        # Assert
        mock_cmdb.assert_called_once_with(
            cmdb_mapping={
                "product_type_name": "nombreevc",
                "product_name": "nombreapp",
                "tag_product": "nombreentorno",
                "product_description": "arearesponsableti",
                "codigo_app": "CodigoApp"
            },
            compact_remote_config_url="http://config_url",
            personal_access_token="access_token_value",
            token_cmdb="cmdb_token",
            host_cmdb="http://cmdb.example.com",
            expression=".*",
            token_defect_dojo="defect_dojo_token",
            host_defect_dojo="http://defectdojo.example.com",
            scan_type="SonarQube API Import",
            tags="sonarqube",
            engagement_name="project_key",
            version="build_execution_id_value",
            build_id="build_id_value",
            source_code_management_uri="http://scm_uri",
            commit_hash="commit_hash_value",
            environment="production",
            branch_tag="branch_name_value",
            service="project_key"
        )
        mock_send_import_scan.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.defect_dojo.report_sonar_defect_dojo.DefectDojo.send_import_scan"
    )
    def test_send_report_no_url_in_response(self, mock_send_import_scan):
        # Arrange
        mock_send_import_scan.return_value = "Error: Scan not sent"

        # Act
        with patch("builtins.print") as mock_print:
            DefectDojoAdapter.send_report(
                "http://config_url",
                "http://scm_uri",
                "production",
                {"token_cmdb": "cmdb_token"},
                {
                    "VULNERABILITY_MANAGER": {
                        "DEFECT_DOJO": { 
                            "HOST_CMDB": "", 
                            "REGEX_EXPRESSION_CMDB": "", 
                            "HOST_DEFECT_DOJO": "",
                            "CMDB_MAPPING_PATH": ""
                        }
                    }
                },
                MagicMock(),
                "project_key"
            )

        # Assert
        mock_print.assert_called_once_with("Error: Scan not sent")