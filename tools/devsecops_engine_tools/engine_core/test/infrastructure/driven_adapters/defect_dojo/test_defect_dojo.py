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
from devsecops_engine_tools.engine_core.src.domain.model.component import Component
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.engagement import (
    Engagement,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
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
            "module": "engine_iac",
            "platform": ["k8s"],
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
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "MAX_RETRIES_QUERY": 5,
                    "REIMPORT_SCAN": True,
                    "CMDB": {
                        "USE_CMDB": True,
                        "HOST_CMDB": "cmdb_host",
                        "REGEX_EXPRESSION_CMDB": "regex",
                        "CMDB_MAPPING_PATH": "mapping_path",
                        "CMDB_MAPPING": {
                            "PRODUCT_TYPE_NAME": "nombreevc",
                            "PRODUCT_NAME": "nombreapp",
                            "TAG_PRODUCT": "nombreentorno",
                            "PRODUCT_DESCRIPTION": "arearesponsableti",
                            "CODIGO_APP": "CodigoApp",
                        },
                        "CMDB_REQUEST_RESPONSE": {
                            "HEADERS": {
                                "Content-Type": "application/json",
                                "tokenkey": "tokenvalue",
                            },
                            "METHOD": "POST",
                            "BODY": {"codapp": "codappvalue"},
                            "RESPONSE": [0],
                        },
                    },
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
                cmdb_request_response={
                    "HEADERS": {
                        "Content-Type": "application/json",
                        "tokenkey": "tokenvalue",
                    },
                    "METHOD": "POST",
                    "BODY": {"codapp": "codappvalue"},
                    "RESPONSE": [0],
                },
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
                test_title="engine_iac_k8s",
                tags="engine_iac_k8s",
                reimport_scan=True,
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

    def test_build_request_with_cmdb(self):
        use_cmdb = True
        tags = "engine_iac_k8s"

        self.vulnerability_management.scan_type = "CHECKOV"
        self.vulnerability_management.input_core = MagicMock()
        self.vulnerability_management.input_core.path_file_results = "file_path"
        self.vulnerability_management.input_core.scope_pipeline = "engagement_name"
        self.vulnerability_management.source_code_management_uri = "source_code_uri"
        self.vulnerability_management.version = "1.0"
        self.vulnerability_management.build_id = "build_id"
        self.vulnerability_management.branch_tag = "trunk"
        self.vulnerability_management.commit_hash = "commit_hash"
        self.vulnerability_management.environment = "dev"

        self.vulnerability_management.config_tool = {
            "VULNERABILITY_MANAGER": {
                "BRANCH_FILTER": "trunk,master,release,develop",
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "REIMPORT_SCAN": True,
                    "MAX_RETRIES_QUERY": 5,
                    "CMDB": {
                        "USE_CMDB": True,
                        "HOST_CMDB": "cmdb_host",
                        "REGEX_EXPRESSION_CMDB": "regex",
                        "CMDB_MAPPING_PATH": "mapping_path",
                        "CMDB_MAPPING": {
                            "PRODUCT_TYPE_NAME": "nombreevc",
                            "PRODUCT_NAME": "nombreapp",
                            "TAG_PRODUCT": "nombreentorno",
                            "PRODUCT_DESCRIPTION": "arearesponsableti",
                            "CODIGO_APP": "CodigoApp",
                        },
                        "CMDB_REQUEST_RESPONSE": {
                            "HEADERS": {
                                "Content-Type": "application/json",
                                "tokenkey": "tokenvalue",
                            },
                            "METHOD": "POST",
                            "BODY": {"codapp": "codappvalue"},
                            "RESPONSE": [0],
                        },
                    },
                },
            }
        }
        self.vulnerability_management.base_compact_remote_config_url = (
            "http://example.com/"
        )
        self.vulnerability_management.access_token = "access_token"

        self.token_cmdb = "token_cmdb"
        self.token_dd = "token_dd"

        self.scan_type_mapping = {"CHECKOV": "Checkov Scan"}
        self.enviroment_mapping = {
            "dev": "Development",
            "qa": "Staging",
            "pdn": "Production",
            "default": "Production",
        }

        with patch(
            "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Connect.cmdb"
        ) as mock_cmdb:
            mock_cmdb.return_value = "cmdb_request_result"

            result = self.defect_dojo._build_request_importscan(
                vulnerability_management=self.vulnerability_management,
                token_cmdb=self.token_cmdb,
                token_dd=self.token_dd,
                scan_type_mapping=self.scan_type_mapping,
                enviroment_mapping=self.enviroment_mapping,
                tags=tags,
                use_cmdb=use_cmdb,
            )

            mock_cmdb.assert_called_once_with(
                cmdb_mapping={
                    "product_type_name": "nombreevc",
                    "product_name": "nombreapp",
                    "tag_product": "nombreentorno",
                    "product_description": "arearesponsableti",
                    "codigo_app": "CodigoApp",
                },
                compact_remote_config_url="http://example.com/mapping_path",
                personal_access_token="access_token",
                token_cmdb=self.token_cmdb,
                host_cmdb="cmdb_host",
                cmdb_request_response={
                    "HEADERS": {
                        "Content-Type": "application/json",
                        "tokenkey": "tokenvalue",
                    },
                    "METHOD": "POST",
                    "BODY": {"codapp": "codappvalue"},
                    "RESPONSE": [0],
                },
                scan_type="Checkov Scan",
                file="file_path",
                engagement_name="engagement_name",
                source_code_management_uri="source_code_uri",
                tags=tags,
                version="1.0",
                build_id="build_id",
                branch_tag="trunk",
                commit_hash="commit_hash",
                service="engagement_name",
                environment="Development",
                token_defect_dojo=self.token_dd,
                host_defect_dojo="host_defect_dojo",
                expression="regex",
                test_title="engine_iac_k8s",
                reimport_scan=True,
            )
            self.assertEqual(result, "cmdb_request_result")

    def test_build_request_without_cmdb(self):
        use_cmdb = False
        tags = "engine_iac_k8s"

        self.vulnerability_management.scan_type = "CHECKOV"
        self.vulnerability_management.input_core = MagicMock()
        self.vulnerability_management.input_core.path_file_results = "file_path"
        self.vulnerability_management.input_core.scope_pipeline = "engagement_name"
        self.vulnerability_management.source_code_management_uri = "source_code_uri"
        self.vulnerability_management.version = "1.0"
        self.vulnerability_management.build_id = "build_id"
        self.vulnerability_management.branch_tag = "trunk"
        self.vulnerability_management.commit_hash = "commit_hash"
        self.vulnerability_management.environment = "dev"
        self.vulnerability_management.vm_product_type_name = "ProductType"
        self.vulnerability_management.vm_product_name = "ProductName"
        self.vulnerability_management.vm_product_description = "ProductDescription"

        self.vulnerability_management.config_tool = {
            "VULNERABILITY_MANAGER": {
                "BRANCH_FILTER": "trunk,master,release,develop",
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "MAX_RETRIES_QUERY": 5,
                    "REIMPORT_SCAN": True,
                    "CMDB": {"USE_CMDB": True, "REGEX_EXPRESSION_CMDB": "regex"},
                },
            }
        }
        self.vulnerability_management.base_compact_remote_config_url = (
            "http://example.com/"
        )
        self.vulnerability_management.access_token = "access_token"

        self.token_cmdb = "token_cmdb"
        self.token_dd = "token_dd"

        self.scan_type_mapping = {"CHECKOV": "Checkov Scan"}
        self.enviroment_mapping = {
            "dev": "Development",
            "qa": "Staging",
            "pdn": "Production",
            "default": "Production",
        }

        with patch(
            "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.ImportScanSerializer"
        ) as mock_serializer:
            mock_serializer().load.return_value = "import_scan_request_result"

            result = self.defect_dojo._build_request_importscan(
                vulnerability_management=self.vulnerability_management,
                token_cmdb=self.token_cmdb,
                token_dd=self.token_dd,
                scan_type_mapping=self.scan_type_mapping,
                enviroment_mapping=self.enviroment_mapping,
                tags=tags,
                use_cmdb=use_cmdb,
            )

            mock_serializer().load.assert_called_once_with(
                {
                    "product_type_name": "ProductType",
                    "product_name": "ProductName",
                    "product_description": "ProductDescription",
                    "code_app": "ProductName",
                    "scan_type": "Checkov Scan",
                    "file": "file_path",
                    "engagement_name": "engagement_name",
                    "source_code_management_uri": "source_code_uri",
                    "tags": tags,
                    "version": "1.0",
                    "build_id": "build_id",
                    "branch_tag": "trunk",
                    "commit_hash": "commit_hash",
                    "service": "engagement_name",
                    "environment": "Development",
                    "token_defect_dojo": self.token_dd,
                    "host_defect_dojo": "host_defect_dojo",
                    "expression": "regex",
                    "test_title": "engine_iac_k8s",
                    "reimport_scan": True,
                }
            )
            self.assertEqual(result, "import_scan_request_result")

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
                    "REIMPORT_SCAN": True,
                    "MAX_RETRIES_QUERY": 5,
                    "CMDB": {"REGEX_EXPRESSION_CMDB": "regex"},
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
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojoPlatform._date_reason_based"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.FindingExclusion.get_finding_exclusion"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_findings_excepted(
        self,
        mock_finding,
        mock_session_manager,
        mock_finding_exclusion,
        mock_date_reason_based,
    ):
        service = "test"
        dict_args = {"module": "engine_iac", "token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                    "REIMPORT_SCAN": True,
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
            # Findings out of scope
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
            # Findings Whitelist
            MagicMock(
                results=[
                    MagicMock(vuln_id_from_tool="CVE-2024-0001", file_path="path1"),
                    MagicMock(vuln_id_from_tool="CVE-2024-0002", file_path="path2"),
                ]
            ),
        ]
        mock_finding.return_value.results = findings_list

        findings_exclusion_list = [
            MagicMock(
                uuid="id1",
                unique_id_from_tool="CVE-2024-0001",
                type="white_list",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            ),
            MagicMock(
                uuid="id2",
                unique_id_from_tool="CVE-2024-0002",
                type="white_list",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            ),
        ]
        mock_finding_exclusion.return_value.results = findings_exclusion_list

        mock_date_reason_based.side_effect = [
            (
                "10012024",
                "10042024",
            ),
            (
                "15012024",
                "10062024",
            ),
            (
                "10062024",
                "",
            ),
            (
                "10062024",
                "",
            ),
            (
                "10012024",
                "",
            ),
            (
                "10012024",
                "",
            ),
            (
                "14082024",
                "15082024",
            ),
            (
                "14082024",
                "15082024",
            ),
            (
                "21022024",
                "29022024",
            ),
            (
                "21022024",
                "29022024",
            ),
        ]

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
                id="id1", where="path1", create_date="10012024", expired_date=""
            ),
            Exclusions(
                id="id2", where="path2", create_date="10012024", expired_date=""
            ),
            Exclusions(
                id="id3", where="pathq", create_date="14082024", expired_date="15082024"
            ),
            Exclusions(
                id="id4", where="path2", create_date="14082024", expired_date="15082024"
            ),
            Exclusions(
                id="id1", where="path1", create_date="21022024", expired_date="29022024"
            ),
            Exclusions(
                id="id2", where="path2", create_date="21022024", expired_date="29022024"
            ),
        ]
        self.assertEqual(result, expected_result)

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.FindingExclusion.get_finding_exclusion"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Finding.get_finding"
    )
    def test_get_findings_excepted_sca(
        self,
        mock_finding,
        mock_session_manager,
        mock_finding_exclusion,
    ):
        service = "test"
        dict_args = {
            "module": "engine_dependencies",
            "token_vulnerability_management": "token1",
        }
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                    "REIMPORT_SCAN": True,
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
            # Findings out of scope
            MagicMock(results=[]),
            # Findings Transferred Finding
            MagicMock(results=[]),
            # Findings Whitelist
            MagicMock(results=[]),
        ]
        mock_finding.side_effect = findings_list

        mock_finding_exclusion.return_value.results = []

        result = self.defect_dojo.get_findings_excepted(
            service, dict_args, secret_tool, config_tool
        )

        mock_session_manager.assert_called_with("token1", "host_defect_dojo")
        mock_finding.assert_called_with(
            session=mock_session_manager.return_value,
            service=service,
            risk_status="On Whitelist",
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
            "module": "engine_dependencies",
            "token_vulnerability_management": "token1",
        }
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                    "REIMPORT_SCAN": True,
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
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.FindingExclusion.get_finding_exclusion"
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
        self,
        mock_exclusions,
        mock_finding,
        mock_session_manager,
        mock_finding_exclusion,
    ):
        service = "test"
        dict_args = {
            "module": "engine_risk",
            "token_vulnerability_management": "token1",
        }
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "LIMITS_QUERY": 80,
                    "REIMPORT_SCAN": True,
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

        findings_exclusion_list = [
            MagicMock(
                uuid="id1",
                unique_id_from_tool="CVE-2024-0001",
                type="white_list",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            ),
            MagicMock(
                uuid="id2",
                unique_id_from_tool="CVE-2024-0002",
                type="white_list",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            ),
        ]
        mock_finding_exclusion.return_value.results = findings_exclusion_list

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
            duplicate="false",
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
                    "REIMPORT_SCAN": True,
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
                    "REIMPORT_SCAN": True,
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
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.DefectDojoPlatform._create_report_exclusion"
    )
    def test_get_report_exclusions(self, mock_create_report_exclusion):
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
                out_of_scope=None,
                risk_status="Transfer Accepted",
            ),
            MagicMock(
                risk_accepted=None,
                out_of_scope=True,
                false_p=None,
                risk_status=None,
            ),
            MagicMock(
                risk_accepted=None,
                out_of_scope=None,
                false_p=None,
                risk_status="On Whitelist",
                vuln_id_from_tool="CVE-2024-0001",
            ),
        ]
        date_fn = MagicMock()
        host_dd = "host_defect_dojo"

        exclusions = self.defect_dojo._get_report_exclusions(
            total_findings, date_fn, host_dd
        )

        assert len(exclusions) == 5

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Engagement"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Component"
    )
    def test_send_sbom_components_success(
        self, mock_component, mock_session_manager, mock_engagement
    ):
        # Configurar los mocks
        mock_engagement.get_engagements.return_value.results = [
            Engagement(id=1, name="test_service")
        ]
        mock_session_manager.return_value = MagicMock()

        mock_component.get_component.return_value.results = []
        mock_component.create_component.return_value = Component(
            name="component_name", version="1.0"
        )

        # Datos de prueba
        sbom_components = [
            Component(name="component1", version="1.0"),
            Component(name="component2", version="2.0"),
        ]
        service = "test_service"
        dict_args = {"token_vulnerability_management": "test_token"}
        secret_tool = {"token_defect_dojo": "secret_token"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "http://defectdojo",
                    "MAX_RETRIES_QUERY": 3,
                    "LIMITS_QUERY": 100,
                    "REIMPORT_SCAN": True,
                }
            }
        }

        # Llamar a la función
        self.defect_dojo.send_sbom_components(
            sbom_components, service, dict_args, secret_tool, config_tool
        )

        # Verificar que se llamaron las funciones esperadas
        mock_session_manager.assert_called_once()
        mock_engagement.get_engagements.assert_called_once()
        assert mock_component.get_component.call_count == 2
        assert mock_component.create_component.call_count == 2

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.Engagement"
    )
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.SessionManager"
    )
    def test_send_sbom_components_exception(
        self, mock_session_manager, mock_engagement
    ):
        # Configurar los mocks
        mock_engagement.get_engagements.side_effect = Exception("Test exception")

        # Datos de prueba
        sbom_components = [Component(name="component1", version="1.0")]
        service = "test_service"
        dict_args = {"token_vulnerability_management": "test_token"}
        secret_tool = {"token_defect_dojo": "secret_token"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "http://defectdojo",
                    "MAX_RETRIES_QUERY": 3,
                    "LIMITS_QUERY": 100,
                    "REIMPORT_SCAN": True,
                }
            }
        }

        # Verificar que se lanza la excepción esperada
        with self.assertRaises(ExceptionVulnerabilityManagement):
            self.defect_dojo.send_sbom_components(
                sbom_components, service, dict_args, secret_tool, config_tool
            )

    def test_date_reason_based_false_positive(self):
        finding = MagicMock()
        finding.last_status_update = "2024-01-10T00:00:00Z"
        date_fn = MagicMock(return_value="10012024")
        reason = self.defect_dojo.FALSE_POSITIVE
        tool = "engine_risk"

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool
        )

        self.assertEqual(create_date, "10012024")
        self.assertEqual(expired_date, date_fn(None))

    def test_date_reason_based_out_of_scope(self):
        finding = MagicMock()
        finding.last_status_update = "2024-01-10T00:00:00Z"
        date_fn = MagicMock(return_value="10012024")
        reason = self.defect_dojo.OUT_OF_SCOPE
        tool = "engine_risk"

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool
        )

        self.assertEqual(create_date, "10012024")
        self.assertEqual(expired_date, date_fn(None))

    def test_date_reason_based_transferred_finding(self):
        finding = MagicMock()
        finding.transfer_finding.date = "2024-08-14"
        finding.transfer_finding.expiration_date = "2024-08-15T00:00:00Z"
        date_fn = MagicMock(side_effect=["14082024", "15082024"])
        reason = self.defect_dojo.TRANSFERRED_FINDING
        tool = "engine_risk"

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool
        )

        self.assertEqual(create_date, "14082024")
        self.assertEqual(expired_date, "15082024")

    def test_date_reason_based_risk_accepted(self):
        finding = MagicMock()
        finding.accepted_risks = [
            {
                "created": "2024-01-10T00:00:00Z",
                "expiration_date": "2024-04-10T00:00:00Z",
            }
        ]
        date_fn = MagicMock(side_effect=["10012024", "10042024"])
        reason = self.defect_dojo.RISK_ACCEPTED
        tool = "engine_risk"

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool
        )

        self.assertEqual(create_date, "10012024")
        self.assertEqual(expired_date, "10042024")

    def test_date_reason_based_on_whitelist_engine_risk(self):
        finding = MagicMock()
        finding.vuln_id_from_tool = "CVE-2024-0001"
        date_fn = MagicMock(side_effect=["21022024", "29022024"])
        reason = self.defect_dojo.ON_WHITELIST
        tool = "engine_risk"
        white_list = [
            MagicMock(
                unique_id_from_tool="CVE-2024-0001",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            )
        ]

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool, white_list=white_list
        )

        self.assertEqual(create_date, "21022024")
        self.assertEqual(expired_date, "29022024")

    def test_date_reason_based_on_whitelist(self):
        finding = MagicMock()
        finding.vulnerability_ids = [{"vulnerability_id": "CVE-2024-0001"}]
        date_fn = MagicMock(side_effect=["21022024", "29022024"])
        reason = self.defect_dojo.ON_WHITELIST
        tool = "engine_container"
        white_list = [
            MagicMock(
                unique_id_from_tool="CVE-2024-0001",
                create_date="2024-02-21T00:00:00Z",
                expiration_date="2024-02-29T00:00:00Z",
            )
        ]

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool, white_list=white_list
        )

        self.assertEqual(create_date, "21022024")
        self.assertEqual(expired_date, "29022024")

    def test_date_reason_based_default(self):
        finding = MagicMock()
        date_fn = MagicMock(return_value="default_date")
        reason = "UNKNOWN_REASON"
        tool = "engine_risk"

        create_date, expired_date = self.defect_dojo._date_reason_based(
            finding, date_fn, reason, tool
        )

        self.assertEqual(create_date, "default_date")
        self.assertEqual(expired_date, "default_date")

    
    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.defect_dojo.defect_dojo.FindingExclusion.get_finding_exclusion"
    )
    def test_get_black_list(self, mock_get_finding_exclusion):
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "DEFECT_DOJO": {
                    "HOST_DEFECT_DOJO": "host_defect_dojo",
                    "MAX_RETRIES_QUERY": 5,
                }
            }
        }

        mock_get_finding_exclusion.return_value.results = [
            MagicMock(unique_id_from_tool="CVE-2024-0001"),
            MagicMock(unique_id_from_tool="CVE-2024-0002"),
        ]

        result = self.defect_dojo.get_black_list(dict_args, secret_tool, config_tool)

        self.assertEqual(result, ["CVE-2024-0001", "CVE-2024-0002"])

    def test_get_black_list_exception(self):
        dict_args = {"token_vulnerability_management": "token1"}
        secret_tool = {"token_defect_dojo": "token2"}
        config_tool = {"VULNERABILITY_MANAGER": {}}

        with self.assertRaises(ExceptionVulnerabilityManagement) as context:
            self.defect_dojo.get_black_list(dict_args, secret_tool, config_tool)
        self.assertIn(
            "Error getting black list with the following error:", str(context.exception)
        )



