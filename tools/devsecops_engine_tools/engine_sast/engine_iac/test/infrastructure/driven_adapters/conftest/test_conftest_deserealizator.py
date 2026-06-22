import unittest
from datetime import datetime
from devsecops_engine_tools.engine_core.src.domain.model.finding import Category, Finding
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.conftest.conftest_deserealizator import (
    ConftestDeserealizator,
)


class TestConftestDeserealizator(unittest.TestCase):
    def setUp(self):
        self.deserealizator = ConftestDeserealizator()

    def test_get_list_finding_empty(self):
        result = self.deserealizator.get_list_finding([], "high", "vulnerability")
        self.assertEqual(result, [])

    def test_get_list_finding_no_failures(self):
        results = [{"filename": "deploy.yaml", "failures": [], "warnings": []}]
        result = self.deserealizator.get_list_finding(results, "high", "vulnerability")
        self.assertEqual(result, [])

    def test_get_list_finding_single_failure(self):
        results = [
            {
                "filename": "deploy.yaml",
                "failures": [
                    {
                        "msg": "Containers must not run as root",
                        "metadata": {"query": "data.main.deny"},
                    }
                ],
            }
        ]
        findings = self.deserealizator.get_list_finding(results, "high", "vulnerability")

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.id, "data.main.deny")  # no metadata.id → fallback to query
        self.assertEqual(finding.description, "Containers must not run as root")
        self.assertEqual(finding.where, "deploy.yaml")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.category, Category.VULNERABILITY)
        self.assertEqual(finding.tool, "Conftest")
        self.assertEqual(finding.module, "engine_iac")

    def test_get_list_finding_where_uses_node_type_and_node_id(self):
        results = [
            {
                "filename": "workflow.json",
                "failures": [
                    {
                        "msg": "Insecure node",
                        "metadata": {
                            "query": "data.n8n.deny",
                            "id": "CONF_N8N_BC_3",
                            "node_type": "n8n-nodes-base.executeCommand",
                            "node_id": "8a77aa44-0f57-4f6b-985a-4b5989138621",
                        },
                    }
                ],
            }
        ]

        findings = self.deserealizator.get_list_finding(results, "high", "vulnerability")
        self.assertEqual(findings[0].where, "workflow.json: n8n-nodes-base.executeCommand.8a77aa44-0f57-4f6b-985a-4b5989138621")

    def test_get_list_finding_uses_rules_config_severity(self):
        results = [
            {
                "filename": "main.tf",
                "failures": [
                    {
                        "msg": "S3 bucket not encrypted",
                        "metadata": {"query": "data.n8n.deny", "id": "CONF_N8N_BC_1"},
                    }
                ],
            }
        ]
        rules_config = {
            "RULES_N8N": {
                "CONF_N8N_BC_1": {"severity": "Critical", "category": "Vulnerability"}
            }
        }
        findings = self.deserealizator.get_list_finding(
            results, "low", "compliance", rules_config=rules_config
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "CONF_N8N_BC_1")
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].category, Category.VULNERABILITY)

    def test_get_list_finding_multiple_files(self):
        results = [
            {
                "filename": "file1.yaml",
                "failures": [
                    {"msg": "Error 1", "metadata": {"query": "data.main.deny"}}
                ],
            },
            {
                "filename": "file2.tf",
                "failures": [
                    {"msg": "Error 2", "metadata": {"query": "data.tf.deny"}},
                    {"msg": "Error 3", "metadata": {"query": "data.tf.deny"}},
                ],
            },
        ]
        findings = self.deserealizator.get_list_finding(results, "medium", "vulnerability")
        self.assertEqual(len(findings), 3)

    def test_get_list_finding_failures_none_handled(self):
        results = [{"filename": "deploy.yaml", "failures": None}]
        findings = self.deserealizator.get_list_finding(results, "high", "vulnerability")
        self.assertEqual(findings, [])

    def test_get_list_finding_rules_config_url_becomes_requirements(self):
        results = [
            {
                "filename": "deploy.yaml",
                "failures": [
                    {
                        "msg": "Missing label",
                        "metadata": {"query": "data.n8n.deny", "id": "CONF_N8N_BC_2"},
                    }
                ],
            }
        ]
        rules_config = {
            "RULES_N8N": {
                "CONF_N8N_BC_2": {
                    "severity": "medium",
                    "category": "vulnerability",
                    "url": "https://example.com/policy",
                }
            }
        }
        findings = self.deserealizator.get_list_finding(
            results, "high", "vulnerability", rules_config=rules_config
        )
        self.assertEqual(findings[0].requirements, "https://example.com/policy")


if __name__ == "__main__":
    unittest.main()
