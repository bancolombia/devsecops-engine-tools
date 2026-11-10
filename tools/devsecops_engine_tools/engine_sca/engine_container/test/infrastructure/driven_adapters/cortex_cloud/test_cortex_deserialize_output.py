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