from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_deserialize_output import (
    XrayDeserializator,
)

import pytest
from unittest.mock import mock_open, patch
import json


@pytest.fixture
def deserializator():
    return XrayDeserializator()

@pytest.fixture
def json_data():
    return [
        {
            "vulnerabilities": [
                {
                    "issue_id": "123",
                    "cves": [{"cvss_v3_score": "7.5"}],
                    "components": {
                        "gav://commons-codec:commons-codec:1.9": {
                            "fixed_versions": [
                                "[1.13]"
                            ],
                            "impact_paths": [
                                [
                                    {
                                        "component_id": "gav://commons-codec:commons-codec:1.9"
                                    }
                                ]
                            ]
                        }
                    },
                    "summary": "Example vulnerability",
                    "severity": "High"
                },
            ]
        }
    ]

def test_get_list_findings_valid(deserializator, json_data):
    with patch("builtins.open", mock_open(read_data=json.dumps(json_data))):
        result = deserializator.get_list_findings("ruta_inexistente.json")
        assert len(result) > 0