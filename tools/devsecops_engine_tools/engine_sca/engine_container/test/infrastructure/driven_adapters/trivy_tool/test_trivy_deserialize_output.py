from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_deserialize_output import (
    TrivyDeserializator
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category
)

import pytest
from unittest.mock import mock_open, patch
import json

@pytest.fixture
def deserializator():
    return TrivyDeserializator()

def test_get_list_vulnerability(deserializator):
        images_scanned = ['nu0429002_devsecops_test_debian:latest_scan_result']
        fake_vulnerabilities = [
            {
            "VulnerabilityID": "CVE-2011-3374",
            "PkgName": "apt",
            "InstalledVersion": "2.6.1",
            "Status": "affected",
            "Title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
            "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
            "Severity": "LOW",
            "CVSS": {
              "nvd": {
                "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "V2Score": 4.3,
                "V3Score": 3.7
              }
            },
            "PublishedDate": "2019-11-26T00:15:11.03Z",
            "LastModifiedDate": "2021-02-09T16:08:18.683Z"
            }
        ]
        fake_json_data = {
            "Results": [{"Vulnerabilities": fake_vulnerabilities}]
        }
        with patch('builtins.open', new_callable=mock_open, read_data=json.dumps(fake_json_data)):
            result = deserializator.get_list_vulnerability(images_scanned)
            assert len(result) == 1