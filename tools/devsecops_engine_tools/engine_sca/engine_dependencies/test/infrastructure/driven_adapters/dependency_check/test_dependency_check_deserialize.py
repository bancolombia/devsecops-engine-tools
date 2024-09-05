from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_deserialize import (
    DependencyCheckDeserialize,
)

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
    


def test_get_list_findings_valid(deserializator, json_data):
    result = deserializator.get_list_findings(json_data)
    assert len(result) > 0
