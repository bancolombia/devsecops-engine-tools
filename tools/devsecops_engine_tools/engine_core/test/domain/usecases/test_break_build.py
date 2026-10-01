import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_core.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
    Priority,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore


class BreakBuildTests(unittest.TestCase):
    def setUp(self):
        self.devops_platform_gateway = Mock()
        self.printer_table_gateway = Mock()
        self.break_build = BreakBuild(
            self.devops_platform_gateway, self.printer_table_gateway
        )

    def test_cross_approval_match_checks_image_and_severity_or_priority(self):
        finding = Finding(
            id="CVE-2026-15157",
            cvss=5.0,
            where="node:24.18.1",
            description="Test vulnerability",
            severity="medium",
            priority=Priority(score=5.0, scale="high"),
            identification_date="2026-10-01",
            published_date_cve="2026-09-01",
            module="engine_container",
            category=Category.VULNERABILITY,
            requirements="",
            tool="PrismaCloud",
        )
        exclusion = Exclusions(
            id="CVE-2026-15157",
            where="all",
            severity="medium",
            **{
                "x86.image.name": [
                    "registry.example/node:24.18.1-builder_20260928"
                ]
            },
        )
        args = {
            "module": "engine_container",
            "image_to_scan": "registry.example/node:24.18.1-builder_20260928",
        }

        excluded, remaining = self.break_build._filter_findings(
            [finding], [exclusion], args
        )
        self.assertEqual(excluded, [finding])
        self.assertEqual(remaining, [])

        args["image_to_scan"] = "registry.example/node:26.9.0-builder_20260928"
        excluded, remaining = self.break_build._filter_findings(
            [finding], [exclusion], args
        )
        self.assertEqual(excluded, [])
        self.assertEqual(remaining, [finding])

        args["image_to_scan"] = "registry.example/node:24.18.1-builder_20260928"
        finding.severity = "low"
        excluded, remaining = self.break_build._filter_findings(
            [finding], [exclusion], args
        )
        self.assertEqual(excluded, [])
        self.assertEqual(remaining, [finding])

        exclusion.priority = "high"
        excluded, remaining = self.break_build._filter_findings(
            [finding], [exclusion], args
        )
        self.assertEqual(excluded, [finding])
        self.assertEqual(remaining, [])

    def test_exclusion_report_prefers_matching_image_specific_reason(self):
        finding = Finding(
            id="CVE-2026-15157",
            cvss=5.0,
            where="undici:6.27.0",
            description="Test vulnerability",
            severity="medium",
            priority=Priority(score=5.0, scale="medium low"),
            identification_date="2026-10-01",
            published_date_cve=None,
            module="engine_container",
            category=Category.VULNERABILITY,
            requirements="fixed in 8.9.0, 7.29.0, 6.28.0",
            tool="PrismaCloud",
        )
        exclusions = [
            Exclusions(
                id="CVE-2026-15157",
                where="all",
                severity="medium",
                reason="base image vulnerability",
            ),
            Exclusions(
                id="CVE-2026-15157",
                where="all",
                severity="medium",
                reason="Prueba Cross",
                **{
                    "x86.image.name": [
                        "artifactory.example/node-rhel:24.18.1-builder_20260928"
                    ]
                },
            ),
        ]
        args = {
            "module": "engine_container",
            "image_to_scan": "artifactory.example/node-rhel:24.18.1-builder_20260928",
        }

        self.break_build._handle_exclusions(
            [finding], exclusions, {"MODEL": "priority"}, args
        )

        reported_exclusions = self.printer_table_gateway.print_table_exclusions.call_args.args[0]
        self.assertEqual(reported_exclusions[0]["reason"], "Prueba Cross")
        self.assertEqual(reported_exclusions[0]["severity"], "medium low")

    @patch("builtins.print")
    def test_process_no_findings(self, mock_print):
        findings_list = []
        input_core = InputCore
        input_core.threshold_defined = Threshold(
            {
                "VULNERABILITY": {
                    "Critical": 1,
                    "High": 3,
                    "Medium": 10,
                    "Low": 15,
                },
                "COMPLIANCE": {"Critical": 1},
                "PRIORITY": {
                    "Very Critical": 1,
                    "Critical": 3,
                    "High": 5,
                    "Medium Low": 15
                },
                "CVE": ["CKV_K8S_22"],
            }
        )
        input_core.totalized_exclusions = []
        input_core.scope_pipeline = "App2"
        input_core.scope_service = "App2"
        input_core.custom_message_break_build = "Custom message"

        self.devops_platform_gateway.message.return_value = "There are no findings"

        args = {"module": "engine_iac"}
        manager = {
            "MODEL": "severity",
            "CLASSIFICATION": ["critical", "high", "medium", "low"]
        }

        result = self.break_build.process(findings_list, input_core, args, False, manager)

        self.assertEqual(
            result, {"findings_excluded": [], "vulnerabilities": {}, "compliances": {}}
        )
        self.devops_platform_gateway.message.assert_called()
        self.devops_platform_gateway.result_pipeline.assert_called_with("succeeded")
        mock_print.assert_called_with("There are no findings")

    def test_process_with_findings_failed(self):
        findings_list = [
            Finding(
                id="CKV_DOCKER_3",
                cvss=None,
                where="/_AW1234/Dockerfile",
                description="Ensure that a user for the container has been created",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_37",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Minimize the admission of containers with capabilities assigned",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_8",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Liveness Probe Should be Configured",
                severity="critical",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.COMPLIANCE,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_20",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Containers should not run with allowPrivilegeEscalation",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_22",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Use read-only filesystem for containers where possible",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_9",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Readiness Probe Should be Configured",
                severity="low",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve="2024-01-17T16:40:49-05:00",
                module="engine_iac",
                category=Category.COMPLIANCE,
                requirements=None,
                tool="Checkov",
            ),
        ]

        input_core = InputCore(
            totalized_exclusions=[Exclusions()],
            threshold_defined=Threshold(
                {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 3,
                        "Medium": 10,
                        "Low": 15,
                    },
                    "COMPLIANCE": {"Critical": 1},
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 10,
                        "Medium Low": 15
                    },
                    "CVE": ["CKV_K8S_22"],
                }
            ),
            path_file_results="results.json",
            custom_message_break_build="message",
            scope_pipeline="test",
            scope_service="test",
            stage_pipeline="Release",
        )

        args = {"module": "engine_container"}
        manager = {
            "MODEL": "severity",
            "CLASSIFICATION": ["critical", "high", "medium", "low"]
        }

        result = self.break_build.process(findings_list, input_core, args, False, manager)

        result_compare = {
            "findings_excluded": [],
            "vulnerabilities": {
                "model_break_build": "severity",
                "threshold": {"critical": 0, "high": 4, "medium": 0, "low": 0},
                "status": "failed",
                "found": [
                    {"id": "CKV_DOCKER_3", "severity": "high", "priority": "high"},
                    {"id": "CKV_K8S_37", "severity": "high", "priority": "high"},
                    {"id": "CKV_K8S_20", "severity": "high", "priority": "high"},
                    {"id": "CKV_K8S_22", "severity": "high", "priority": "high"},
                ],
            },
            "compliances": {
                "threshold": {"critical": 1},
                "status": "failed",
                "found": [
                    {"id": "CKV_K8S_8", "severity": "critical", "priority": "high"},
                    {"id": "CKV_K8S_9", "severity": "low", "priority": "high"},
                ],
            },
        }

        assert result == result_compare

    def test_process_with_findings_warning(self):
        findings_list = [
            Finding(
                id="CKV_DOCKER_3",
                cvss=None,
                where="/_AW1234/Dockerfile",
                description="Ensure that a user for the container has been created",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_20",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Containers should not run with allowPrivilegeEscalation",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
        ]

        input_core = InputCore(
            totalized_exclusions=[Exclusions()],
            threshold_defined=Threshold(
                {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 8,
                        "Medium": 10,
                        "Low": 15,
                    },
                    "COMPLIANCE": {"Critical": 1},
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 10,
                        "Medium Low": 15
                    }
                }
            ),
            path_file_results="results.json",
            custom_message_break_build="message",
            scope_pipeline="test",
            scope_service="test",
            stage_pipeline="Release",
        )

        manager = {
            "MODEL": "severity",
            "CLASSIFICATION": ["critical", "high", "medium", "low"]
        }
        result = self.break_build.process(
            findings_list, input_core, {"module": "engine_iac"}, False, manager
        )

        result_compare = {
            "findings_excluded": [],
            "vulnerabilities": {
                "model_break_build": "severity",
                "threshold": {"critical": 0, "high": 2, "medium": 0, "low": 0},
                "status": "succeeded",
                "found": [
                    {"id": "CKV_DOCKER_3", "severity": "high", "priority": "high"},
                    {"id": "CKV_K8S_20", "severity": "high", "priority": "high"},
                ],
            },
            "compliances": {},
        }

        assert result == result_compare

    def test_process_with_findings_succeeded(self):
        findings_list = [
            Finding(
                id="CKV_DOCKER_3",
                cvss=None,
                where="/_AW1234/Dockerfile",
                description="Ensure that a user for the container has been created",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
            Finding(
                id="CKV_K8S_20",
                cvss=None,
                where="/_AW1234/app.yaml",
                description="Containers should not run with allowPrivilegeEscalation",
                severity="high",
                priority= Priority(score=7.0, scale="high"),
                identification_date="19012024",
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Checkov",
            ),
        ]

        input_core = InputCore(
            totalized_exclusions=[
                Exclusions(
                    id="CKV_DOCKER_3",
                    where="/_AW1234/Dockerfile",
                    cve_id="",
                    create_date="18112023",
                    expired_date="06052024",
                    severity="high",
                    hu="34243",
                ),
                Exclusions(
                    id="CKV_K8S_20",
                    where="/_AW1234/app.yaml",
                    cve_id="",
                    create_date="18112023",
                    expired_date="06052024",
                    severity="high",
                    hu="34243",
                ),
            ],
            threshold_defined=Threshold(
                {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 8,
                        "Medium": 10,
                        "Low": 15,
                    },
                    "COMPLIANCE": {"Critical": 1},
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 5,
                        "Medium Low": 15
                    }
                }
            ),
            path_file_results="results.json",
            custom_message_break_build="message",
            scope_pipeline="test",
            scope_service="test",
            stage_pipeline="Release",
        )

        manager = {
            "MODEL": "severity",
            "CLASSIFICATION": ["critical", "high", "medium", "low"]
        }
        result = self.break_build.process(
            findings_list, input_core, {"module": "engine_iac"}, False, manager
        )

        result_compare = {
            "findings_excluded": [
                {"id": "CKV_DOCKER_3", "severity": "high", "priority": "high", "category": Category.VULNERABILITY.value},
                {"id": "CKV_K8S_20", "severity": "high", "priority": "high", "category": Category.VULNERABILITY.value},
            ],
            "vulnerabilities": {},
            "compliances": {},
        }

        self.assertEqual(result, result_compare)