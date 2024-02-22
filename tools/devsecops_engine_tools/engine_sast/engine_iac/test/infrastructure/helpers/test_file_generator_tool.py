from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)
import json
from functools import reduce

def test_generate_file_from_tool():
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
                            "result": "FAILED"
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
        {
            "check_type": "cloudformation",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "bc_check_id": None,
                        "check_name": "Ensure the S3 bucket does not allow READ permissions to everyone",
                        "check_result": {
                            "result": "FAILED"
                        },
                        "code_block": None,
                        "file_path": "/template-cloudfront.yaml",
                        "file_abs_path": "/test_path/_AW1234/template-cloudfront.yaml",
                        "repo_file_path": "/_AW1234/template-cloudfront.yaml",
                        "file_line_range": [308, 339],
                        "resource": "AWS::S3::Bucket.S3BucketCaptchaEdin",
                        "evaluations": {},
                        "check_class": "checkov.cloudformation.checks.resource.aws.S3PublicACLRead",
                        "fixed_definition": None,
                        "entity_tags": {},
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
        }
    ]
    rules_doc = {
        "CKV_DOCKER_3": {
            "checkID": "IAC-CKV-DOCKER-3 Ensure that a user for the container has been created",
            "guideline": "guideline",
            "severity": "High",
            "cvss": "",
            "category": "Vulnerability",
        },
        "CKV_K8S_13": {
            "checkID": "IAC-CKV_K8S_13 Ensure memory limits are set",
            "guideline": "guideline",
            "severity": "High",
            "cvss": "",
            "category": "Compliance",
        },
        "CKV_AWS_20": {
            "customID": "C-S3-005",
            "checkID": "IAC-CKV_K8S_13 Ensure memory limits are set",
            "guideline": "guideline",
            "severity": "High",
            "cvss": "",
            "category": "Compliance",
        },
    }

    absolute_path = generate_file_from_tool("CHECKOV", results_scan_list, rules_doc)

    with open(absolute_path, "r") as file:
        data = file.read()
        json_data = json.loads(data)
        assert len(json_data["results"]["failed_checks"]) ==  reduce(lambda x, y: x + y, map(lambda x: len(x["results"]["failed_checks"]), results_scan_list))


def test_generate_file_from_tool_Exception():
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
                            "result": "FAILED"
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
        {
            "check_type": "cloudformation",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "bc_check_id": None,
                        "check_name": "Ensure the S3 bucket does not allow READ permissions to everyone",
                        "check_result": {
                            "result": "FAILED"
                        },
                        "code_block": None,
                        "file_path": "/template-cloudfront.yaml",
                        "file_abs_path": "/test_path/_AW1234/template-cloudfront.yaml",
                        "repo_file_path": "/_AW1234/template-cloudfront.yaml",
                        "file_line_range": [308, 339],
                        "resource": "AWS::S3::Bucket.S3BucketCaptchaEdin",
                        "evaluations": {},
                        "check_class": "checkov.cloudformation.checks.resource.aws.S3PublicACLRead",
                        "fixed_definition": None,
                        "entity_tags": {},
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
        }
    ]

    absolute_path = generate_file_from_tool("CHECKOV", results_scan_list, None)

    assert absolute_path == None