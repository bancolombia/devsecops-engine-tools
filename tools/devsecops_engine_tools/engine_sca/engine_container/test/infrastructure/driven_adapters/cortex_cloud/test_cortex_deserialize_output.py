import json

import pytest

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_deserialize_output import (
    CortexDeserealizator,
)


def test_cortex_deserializer_maps_scanner_results_to_shared_models(tmp_path):
    result_file = tmp_path / "cortex.json"
    result_file.write_text(
        json.dumps(
            {
                "imageName": "biometriafacial:latest",
                "scannersResults": [
                    {
                        "vulnerabilities": [
                            {
                                "cveId": "CVE-2026-1234",
                                "severity": "HIGH",
                                "packageName": "openssl",
                                "packageVersion": "3.0.0",
                                "fixVersions": ["3.0.1"],
                                "cvssScore": 8.1,
                                "description": "Example vulnerability",
                            }
                        ]
                    }
                ],
            }
        )
    )

    deserializer = CortexDeserealizator()
    findings = deserializer.get_list_findings(str(result_file))
    contexts = deserializer.get_container_context_from_results(str(result_file))

    assert len(findings) == len(contexts) == 1
    assert findings[0].id == "CVE-2026-1234"
    assert findings[0].tool == "CortexCloud"
    assert findings[0].severity == "high"
    assert contexts[0].target_image == "biometriafacial:latest"
    assert contexts[0].fixed_version == "3.0.1"


def test_cortex_deserializer_rejects_unknown_output_schema(tmp_path):
    result_file = tmp_path / "cortex.json"
    result_file.write_text('{"unexpected": []}')

    with pytest.raises(ValueError, match="Unsupported Cortex Cloud"):
        CortexDeserealizator().get_list_findings(str(result_file))

def test_cortex_deserializer_maps_real_xdm_findings(tmp_path):
    result_file = tmp_path / "cortex.json"
    result_file.write_text(
        json.dumps(
            {
                "asset_name": "eclipse:test",
                "analysis": [
                    {"type": "Malware", "distribution": {"total": 0}},
                    {
                        "type": "Vulnerabilities",
                        "findings": [
                            {
                                "xdm.finding.description": "CVE found in package zlib",
                                "xdm.finding.observation_time": 1794609080190,
                                "xdm.finding.normalized_fields": {
                                    "xdm.software_package.id": "zlib",
                                    "xdm.software_package.version": "1.3.2-r0",
                                    "xdm.vulnerability.cve_id": "CVE-2026-4738",
                                    "xdm.vulnerability.cvss_score": 9.4,
                                    "xdm.vulnerability.cvss_vector": "",
                                    "xdm.vulnerability.fix_versions": ["1.4-r0"],
                                    "xdm.vulnerability.publish_date": 1774325849,
                                    "xdm.vulnerability.severity": "critical",
                                    "xdm.vulnerability.status": "fixed in 1.4-r0",
                                },
                            }
                        ],
                    },
                ],
            }
        )
    )

    deserializer = CortexDeserealizator()
    findings = deserializer.get_list_findings(str(result_file))
    contexts = deserializer.get_container_context_from_results(str(result_file))

    assert len(findings) == len(contexts) == 1
    assert findings[0].id == "CVE-2026-4738"
    assert findings[0].severity == "critical"
    assert findings[0].where == "zlib:1.3.2-r0"
    assert findings[0].identification_date is not None
    assert contexts[0].target_image == "eclipse:test"
    assert contexts[0].fixed_version == "1.4-r0"
