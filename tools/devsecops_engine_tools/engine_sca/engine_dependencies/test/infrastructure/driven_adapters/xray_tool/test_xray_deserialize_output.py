from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_deserialize_output import (
    XrayDeserializator,
)

import pytest
from unittest.mock import mock_open, patch
import json


@pytest.fixture
def deserializator():
    return XrayDeserializator()


def test_get_list_findings(deserializator):
    mock_json_data = {
        "vulnerabilities": [
            {
                "severity": "Critical",
                "impactedPackageName": "com.alibaba:fastjson",
                "impactedPackageVersion": "1.2.24",
                "summary": "Alibaba fastjson autoType Restrictions Bypass Object Deserialization Remote Code Execution",
                "fixedVersions": ["[1.2.48]"],
                "cves": [{"id": "", "cvssV2": "10.0", "cvssV3": "9.8"}],
                "issueId": "XRAY-93075",
            }
        ]
    }
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(mock_json_data)
    ):
        result = deserializator.get_list_findings(mock_json_data)
        assert len(result) == 1
