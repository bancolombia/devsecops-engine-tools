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
                    "MAX_RETRIES_QUERY": 5,
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
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Product.get_product"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Connect.get_code_app"
    )
    def test_get_product_type_service(
        self, cmdb_code, mock_product, mock_session_manager
    ):
        service = "test"
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = None
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                    "MAX_RETRIES_QUERY": 5,
                    "REGEX_EXPRESSION_CMDB": "regex",
                }
            }
        }

        mock_session_manager.return_value = MagicMock()

        cmdb_code.return_value = "CodigoApp"

        product_list = [
            MagicMock(
                results=[
                    MagicMock(
                        id=1,
                        name="name1",
                        prod_type=35,
                    ),
                ],
                prefetch=MagicMock(),
            )
        ]
        mock_product.side_effect = product_list

        result = self.defect_dojo.get_product_type_service(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        self.assertIsNotNone(result)

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
                    "MAX_RETRIES_QUERY": 5,
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
            # Findings Transferred Finding
            MagicMock(
                results=[
                    MagicMock(
                        vuln_id_from_tool="id3",
                        file_path="path1",
                        transfer_finding=MagicMock(
                            date="2024-08-14",
                            expiration_date="2024-08-15T00:00:00Z",
                        ),
                    ),
                    MagicMock(
                        vuln_id_from_tool="id4",
                        file_path="path2",
                        transfer_finding=MagicMock(
                            date="2024-08-14",
                            expiration_date="2024-08-15T00:00:00Z",
                        ),
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
            Exclusions(
                id="id3", where="pathq", create_date="14082024", expired_date="15082024"
            ),
            Exclusions(
                id="id4", where="path2", create_date="14082024", expired_date="15082024"
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
                    "MAX_RETRIES_QUERY": 5,
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
            ),
            # Findings false positive
            MagicMock(results=[]),
            # Findings Transferred Finding
            MagicMock(results=[]),
        ]
        mock_finding.side_effect = findings_list

        result = self.defect_dojo.get_findings_excepted(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        mock_finding.assert_called_with(
            session=mock_session_manager.return_value,
            service=service,
            risk_status="Transfer Accepted",
            tags="engine_dependencies",
            limit=80,
        )

        expected_result = [
            Exclusions(id="id1", where="comp1:version1", create_date="21022024"),
            Exclusions(id="id2", where="comp2:version2", create_date="21022024"),
        ]
        self.assertEqual(result, expected_result)

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_findings_excepted_retry(self, mock_finding, mock_session_manager):

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
                    "MAX_RETRIES_QUERY": 2,
                }
            }
        }

        mock_session_manager.return_value = MagicMock()
        mock_finding.side_effect = Exception("Simulated error")

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_findings_excepted(
                service, dict_args, secret_tool, config_tool
            )

        assert "Error getting excepted findings with the following error:" in str(
            context.exception
        )

    def test_get_findings_excepted_exception(self):

        service = "test"
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {"VULNERABILITY_MANAGER": {}}

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_findings_excepted(
                service, dict_args, secret_tool, config_tool
            )
        assert "Error getting excepted findings with the following error:" in str(
            context.exception
        )

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojoPlatform._format_date_to_dd_format"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojoPlatform._get_report_exclusions"
    )
    def test_get_all(
        self, mock_exclusions, mock_finding, mock_session_manager, mock_format_date
    ):
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
                    "MAX_RETRIES_QUERY": 5,
                }
            }
        }

        mock_session_manager.return_value = MagicMock()
        findings_list = [
            # file_path
            MagicMock(
                id="id1",
                status="active",
                where="path",
                tags=["test1"],
                severity="sev1",
                age=10,
                active=True,
                risk_status="risk",
                created="2024-02-21T00:00:00Z",
                last_reviewed="2024-02-21T00:00:00Z",
                last_status_update="2024-02-21T00:00:00Z",
                epss_score=0.5,
                epss_percentile=0.5,
                vul_description="description",
            ),
            # endpoints
            MagicMock(
                id="id2",
                status="active",
                where="path",
                tags=["test2"],
                severity="sev2",
                age=10,
                active=True,
                risk_status="risk",
                created="2024-02-21T00:00:00Z",
                last_reviewed="2024-02-21T00:00:00Z",
                last_status_update="2024-02-21T00:00:00Z",
                epss_score=0.5,
                epss_percentile=0.5,
                vul_description="description",
            ),
            # component_name + component_version
            MagicMock(
                id="id3",
                status="active",
                where="path",
                tags=["test3"],
                severity="sev3",
                age=10,
                active=True,
                risk_status="risk",
                created="2024-02-21T00:00:00Z",
                last_reviewed="2024-02-21T00:00:00Z",
                last_status_update="2024-02-21T00:00:00Z",
                epss_score=0.5,
                epss_percentile=0.5,
                vul_description="description",
            ),
        ]
        mock_finding.return_value.results = findings_list
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

        result, exclusions = self.defect_dojo.get_all(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        mock_finding.assert_called_with(
            session=mock_session_manager.return_value,
            service=service,
            limit=80,
        )
        mock_exclusions.assert_called_once()
        assert exclusions == mock_exclusions.return_value
        self.assertEqual(result, expected_result)

    def test_get_all_findings_exception(self):
        service = "test"
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {"VULNERABILITY_MANAGER": {}}

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_all(service, dict_args, secret_tool, config_tool)
        assert "Error getting all findings with the following error:" in str(
            context.exception
        )

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.ImportScanRequest"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Engagement"
    )
    def test_get_active_engagements(self, mock_engagement, mock_import_scan_request):
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = MagicMock()
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 999,
                }
            }
        }
        engagement_name = "engagement_name"
        mock_engagement.get_engagements.return_value = MagicMock()

        self.defect_dojo.get_active_engagements(
            engagement_name, dict_args, secret_tool, config_tool
        )

        mock_import_scan_request.assert_called_once()
        mock_engagement.get_engagements.assert_called_once()

    def test_get_active_engagements_exception(self):
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = MagicMock()
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 999,
                }
            }
        }
        engagement_name = "engagement_name"

        with unittest.TestCase().assertRaises(Exception) as context:
            self.defect_dojo.get_active_engagements(
                engagement_name, dict_args, secret_tool, config_tool
            )
        assert "Error getting engagements with the following error:" in str(
            context.exception
        )

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojoPlatform._create_exclusion"
    )
    def test_get_report_exclusions(self, mock_create_exclusion):
        total_findings = [
            MagicMock(
                risk_accepted=True,
            ),
            MagicMock(
                risk_accepted=None,
                false_p=True,
            ),
            MagicMock(
                risk_accepted=None,
                false_p=None,
                risk_status="Transfer Accepted",
            ),
            MagicMock(
                risk_accepted=None,
                false_p=None,
                risk_status=None,
            ),
        ]
        date_fn = MagicMock()

        exclusions = self.defect_dojo._get_report_exclusions(total_findings, date_fn)

        assert len(exclusions) == 3
