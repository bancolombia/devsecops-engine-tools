import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo import (
    DefectDojoPlatform,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.report import Report
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement,
)


class TestDefectDojoPlatform(unittest.TestCase):
    def setUp(self):
        self.vulnerability_management = VulnerabilityManagement
        self.defect_dojo = DefectDojoPlatform()

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojo.send_import_scan"
    )
    def test_send_vulnerability_management(self, mock_send_import_scan):
        self.vulnerability_management.dict_args = {
            "token_vulnerability_management": "token1",
            "token_cmdb": "token2",
            "tool": "engine_iac",
        }
        self.vulnerability_management.secret_tool = {
            "token_defect_dojo": "token3",
            "token_cmdb": "token4",
        }
        self.vulnerability_management.base_compact_remote_config_url = (
            "http://example.com/"
        )
        self.vulnerability_management.config_tool = {
            "VULNERABILITY_MANAGER": {
                "BRANCH_FILTER": "trunk,master,release,develop",
                "DEFECT_DOJO": {
                    "CMDB_MAPPING_PATH": "mapping_path",
                    "HOST_CMDB": "cmdb_host",
                    "REGEX_EXPRESSION_CMDB": "regex",
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                },
            }
        }
        self.vulnerability_management.access_token = "access_token"
        self.vulnerability_management.scan_type = "CHECKOV"
        self.vulnerability_management.input_core = MagicMock()
        self.vulnerability_management.input_core.scope_pipeline = "engagement_name"
        self.vulnerability_management.input_core.path_file_results = "file_path"
        self.vulnerability_management.version = "1.0"
        self.vulnerability_management.build_id = "build_id"
        self.vulnerability_management.source_code_management_uri = "source_code_uri"
        self.vulnerability_management.branch_tag = "trunk"
        self.vulnerability_management.commit_hash = "commit_hash"
        self.vulnerability_management.environment = "dev"

        with patch(
            "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Connect.cmdb"
        ) as mock_cmdb:
            mock_cmdb.return_value = MagicMock()
            mock_send_import_scan.return_value = MagicMock(url="http://example.com/")

            self.defect_dojo.send_vulnerability_management(
                self.vulnerability_management
            )

            mock_cmdb.assert_called_with(
                cmdb_mapping={
                    "product_type_name": "nombreevc",
                    "product_name": "nombreapp",
                    "tag_product": "nombreentorno",
                    "product_description": "arearesponsableti",
                    "codigo_app": "CodigoApp",
                },
                compact_remote_config_url="http://example.com/mapping_path",
                personal_access_token="access_token",
                token_cmdb="token2",
                host_cmdb="cmdb_host",
                expression="regex",
                token_defect_dojo="token1",
                host_defect_dojo="host_defect_dojo",
                scan_type="Checkov Scan",
                engagement_name="engagement_name",
                service="engagement_name",
                file="file_path",
                version="1.0",
                build_id="build_id",
                source_code_management_uri="source_code_uri",
                branch_tag="trunk",
                commit_hash="commit_hash",
                environment="Development",
                tags="engine_iac",
            )

    def test_send_vulnerability_management_exception(self):
        self.vulnerability_management.config_tool = {
            "VULNERABILITY_MANAGER": {
                "BRANCH_FILTER": "trunk,master,release,develop",
            }
        }
        self.vulnerability_management.branch_tag = "trunk"

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.send_vulnerability_management(
                self.vulnerability_management
            )
        assert (
            "Error sending report to vulnerability management with the following error:"
            in str(context.exception)
        )

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_findings_excepted(self, mock_finding, mock_session_manager):
        service = "test"
        dict_args = {"tool": "engine_iac", "token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                }
            }
        }

        mock_session_manager.return_value = MagicMock()
        findings_list = [
            # Findings risk accepted
            MagicMock(
                results=[
                    MagicMock(
                        vuln_id_from_tool="id1",
                        file_path="path1",
                        accepted_risks=[
                            {
                                "created": "2024-01-10T00:00:00Z",
                                "expiration_date": "2024-04-10T00:00:00Z",
                            },
                        ],
                    ),
                    MagicMock(
                        vuln_id_from_tool="id2",
                        file_path="path2",
                        accepted_risks=[
                            {
                                "created": "2024-01-15T00:00:00Z",
                                "expiration_date": "2024-06-10T00:00:00Z",
                            }
                        ],
                    ),
                ]
            ),
            # Findings false positive
            MagicMock(
                results=[
                    MagicMock(
                        vuln_id_from_tool="id1",
                        file_path="path1",
                        last_status_update="2024-01-10T00:00:00Z",
                    ),
                    MagicMock(
                        vuln_id_from_tool="id2",
                        file_path="path2",
                        last_status_update="2024-01-10T00:00:00Z",
                    ),
                ]
            ),
        ]
        mock_finding.side_effect = findings_list

        result = self.defect_dojo.get_findings_excepted(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")

        expected_result = [
            Exclusions(
                id="id1", where="path1", create_date="10012024", expired_date="10042024"
            ),
            Exclusions(
                id="id2", where="path2", create_date="15012024", expired_date="10062024"
            ),
            Exclusions(
                id="id2", where="path2", create_date="10062024", expired_date=""
            ),
            Exclusions(
                id="id2", where="path2", create_date="10062024", expired_date=""
            ),
        ]
        self.assertEqual(result, expected_result)

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_findings_excepted_sca(self, mock_finding, mock_session_manager):
        service = "test"
        dict_args = {
            "tool": "engine_dependencies",
            "token_vulnerability_management": "token1",
        }
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                }
            }
        }

        mock_session_manager.return_value = MagicMock()
        findings_list = [
            MagicMock(
                vuln_id_from_tool="id1",
                component_name="comp1",
                component_version="version1",
                last_status_update="2024-02-21T00:00:00Z",
                accepted_risks=[
                    {
                        "created": "2024-02-21T00:00:00Z",
                        "expiration_date": "2024-02-29T00:00:00Z",
                    }
                ],
            ),
            MagicMock(
                vuln_id_from_tool="id2",
                component_name="comp2",
                component_version="version2",
                last_status_update="2024-02-21T00:00:00Z",
                accepted_risks=[
                    {
                        "created": "2024-02-21T00:00:00Z",
                        "expiration_date": "2024-03-30T00:00:00Z",
                    }
                ],
            ),
        ]
        mock_finding.return_value.results = findings_list

        result = self.defect_dojo.get_findings_excepted(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        mock_finding.assert_called_with(
            session=mock_session_manager.return_value,
            service=service,
            false_p=True,
            tags="engine_dependencies",
            limit=80,
        )

        expected_result = [
            Exclusions(
                id="id1",
                where="comp1:version1",
                create_date="21022024"
            ),
            Exclusions(
                id="id2",
                where="comp2:version2",
                create_date="21022024"
            ),
            Exclusions(
                id="id2",
                where="comp2:version2",
                create_date="21022024"
            ),
            Exclusions(
                id="id2",
                where="comp2:version2",
                create_date="21022024"
            ),
        ]
        self.assertEqual(result, expected_result)

    def test_get_findings_excepted_exception(self):

        service = "test"
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {"VULNERABILITY_MANAGER": {}}

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_findings_excepted(
                service, dict_args, secret_tool, config_tool
            )
        assert (
            "Error getting excepted findings with the following error:"
            in str(context.exception)
        )

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_all_findings(self, mock_finding, mock_session_manager):
        service = "test"
        dict_args = {
            "tool": "engine_risk",
            "token_vulnerability_management": "token1",
        }
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                }
            }
        }

        mock_session_manager.return_value = MagicMock()
        findings_list = [
            # file_path
            MagicMock(
                vuln_id_from_tool="id1",
                date="2024-02-21T00:00:00Z",
                display_status="stat1",
                file_path="path",
                tags=["test1"],
                severity="sev1",
                active=True,
            ),
            # endpoints
            MagicMock(
                vuln_id_from_tool="id2",
                date="2024-02-21T00:00:00Z",
                display_status="stat2",
                endpoints="endpoint",
                tags=["engine_dast"],
                severity="sev2",
                active=True,
            ),
            # component_name + component_version
            MagicMock(
                vuln_id_from_tool="id3",
                date="2024-02-21T00:00:00Z",
                display_status="stat3",
                component_name="name",
                component_version="v1",
                tags=["engine_container"],
                severity="sev3",
                active=True,
            ),
        ]
        mock_finding.return_value.results = findings_list

        result = self.defect_dojo.get_all_findings(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        mock_finding.assert_called_with(
            session=mock_session_manager.return_value,
            service=service,
            limit=80,
        )

        expected_result = [
            Report(
                id="id2",
                date="21022024",
                status="stat2",
                where="path",
                tags=["test1"],
                severity="sev1",
                active=True,
            ),
            Report(
                id="id2",
                date="21022024",
                status="stat2",
                where="endpoint",
                tags=["engine_dast"],
                severity="sev2",
                active=True,
            ),
            Report(
                id="id3",
                date="21022024",
                status="stat3",
                where="name:v1",
                tags=["engine_container"],
                severity="sev3",
                active=True,
            ),
        ]
        self.assertEqual(result, expected_result)

    def test_get_all_findings_exception(self):

        service = "test"
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {"VULNERABILITY_MANAGER": {}}

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_all_findings(
                service, dict_args, secret_tool, config_tool
            )
        assert (
            "Error getting all findings with the following error:"
            in str(context.exception)
        )