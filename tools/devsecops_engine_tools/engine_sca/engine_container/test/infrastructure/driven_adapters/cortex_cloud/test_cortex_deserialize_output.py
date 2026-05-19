import json
from unittest.mock import mock_open, patch

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_deserialize_output import (
    CortexDeserealizator,
)


def test_get_list_findings_maps_cortex_tool_and_severity():
    payload = {
        "results": [
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "cvss": 7.5,
                        "packageName": "openssl",
                        "packageVersion": "3.0.0",
                        "description": "Vulnerability description",
                        "severity": "important",
                        "discoveredDate": "2026-05-19T10:30:00+0000",
                        "publishedDate": "2026-05-01T00:00:00Z",
                        "status": "open",
                    }
                ]
            }
        ]
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(payload).encode("utf-8"))):
        findings = CortexDeserealizator().get_list_findings("result.json")

    assert len(findings) == 1
    assert findings[0].id == "CVE-2026-0001"
    assert findings[0].where == "openssl:3.0.0"
    assert findings[0].severity == "high"
    assert findings[0].tool == "CortexCloud"
