from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_deserealizator import (
    CheckovDeserealizator,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from datetime import datetime

def test_get_list_finding():
    results_scan_list = [
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_3",
                        "bc_check_id": None,
                        "check_name": "Ensure that a user for the container has been created",
                        "check_result": {
                            "result": "FAILED",
                            "results_configuration": None,
                        },
                        "code_block": None,
                        "file_path": "/Dockerfile",
                        "file_abs_path": "./_AW1234/Dockerfile",
                        "repo_file_path": "/_AW1234/Dockerfile",
                    }
                ]
            },
            "summary": {
                "passed": 1,
                "failed": 1,
                "skipped": 0,
                "parsing_errors": 0,
                "resource_count": 1,
                "checkov_version": "2.3.296",
            },
        },
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_13",
                        "bc_check_id": None,
                        "check_name": "Minimize the admission of containers with capabilities assigned",
                        "check_result": {
                            "result": "FAILED",
                            "evaluated_keys": [...],
                        },
                        "code_block": None,
                        "file_path": "/app.yaml",
                        "file_abs_path": "./_AW1234/app.yaml",
                        "repo_file_path": "/_AW1234/app.yaml",
                        "file_line_range": [21, 83],
                        "resource": "Deployment.devsecops-engine-dev.ms-async-provider-deployment",
                        "evaluations": {},
                        "check_class": "checkov.kubernetes.checks.resource.k8s.MinimizeCapabilities",
                        "fixed_definition": None,
                        "entity_tags": None,
                    }
                ]
            },
            "summary": {
                "passed": 15,
                "failed": 9,
                "skipped": 0,
                "parsing_errors": 0,
                "resource_count": 7,
                "checkov_version": "2.3.296",
            },
        },
    ]
    config_rules = {
        "CKV_DOCKER_3": {
            "checkID": "IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
            "environment": {...},
            "guideline": "guideline",
            "severity": "High",
            "cvss": "",
            "category": "Vulnerability",
        },
        "CKV_K8S_13": {
            "checkID": "IAC-CKV_K8S_13 Ensure memory limits are set",
            "environment": {...},
            "guideline": "guideline",
            "severity": "High",
            "cvss": "",
            "category": "Compliance",
        },
    }

    list_findings = CheckovDeserealizator.get_list_finding(
        results_scan_list, config_rules
    )

    list_findings_compare: list[Finding] = []
    list_findings_compare.append(
        Finding(
            id="CKV_DOCKER_3",
            cvss=None,
            where="/_AW1234/Dockerfile",
            description="IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
            severity="high",
            identification_date=datetime.now().strftime("%d%m%Y"),
            published_date_cve=None,
            module="engine_iac",
            category=Category.VULNERABILITY,
            requirements=None,
            tool="Checkov",
        )
    )

    list_findings_compare.append(
        Finding(
            id="CKV_K8S_13",
            cvss=None,
            where="/_AW1234/app.yaml",
            description='IAC-CKV_K8S_13 Ensure memory limits are set',
            severity="high",
            identification_date=datetime.now().strftime("%d%m%Y"),
            published_date_cve=None,
            module="engine_iac",
            category=Category.COMPLIANCE,
            requirements=None,
            tool="Checkov",
        )
    )

    assert list_findings == list_findings_compare
