from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_deserialize import (
    DependencyCheckDeserialize,
)
from unittest.mock import patch
import pytest

@pytest.fixture
def deserializator():
    return DependencyCheckDeserialize()


@pytest.fixture
def json_data():
    return {
        "dependencies": [
            {
                "fileName": "path/to/package1:1.0",
                "vulnerabilities": [
                    {
                        "name": "CVE-1234",
                        "cvssv3": 7.5,
                        "description": "Una vulnerabilidad alta en package1.",
                        "severity": "HIGH"
                    }
                ]
            }
        ]
    }
    

@patch.object(DependencyCheckDeserialize, 'load_results')
def test_get_list_findings_valid(mock_load_results, deserializator, json_data):
    mock_load_results.return_value = json_data

    result = deserializator.get_list_findings(None)

    assert len(result) > 0
    assert result[0].id == "CVE-1234"
    assert result[0].cvss == "7.5"
    assert result[0].severity == "high"
