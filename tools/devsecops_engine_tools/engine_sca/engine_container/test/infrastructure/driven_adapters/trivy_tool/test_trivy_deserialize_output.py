from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_deserialize_output import (
    TrivyDeserializator,
)

import pytest
from unittest.mock import mock_open, patch
import json


@pytest.fixture
def deserializator():
    return TrivyDeserializator()


def test_get_list_findings(deserializator):
    images_scanned = ["nu0429002_devsecops_test_debian:latest_scan_result"]
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
                    "V3Score": 3.7,
                }
            },
            "PublishedDate": "2019-11-26T00:15:11.03Z",
            "LastModifiedDate": "2021-02-09T16:08:18.683Z",
        }
    ]
    fake_json_data = {"Results": [{"Vulnerabilities": fake_vulnerabilities}]}
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)
    ):
        result = deserializator.get_list_findings(images_scanned)
        assert len(result) == 1

def test_get_container_context_from_results():
    from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_deserialize_output import TrivyDeserializator
from unittest.mock import patch, mock_open
import json

def test_get_container_context_from_results():
    fake_vulnerabilities = [
        {
            "VulnerabilityID": "CVE-2011-3374",
            "PkgName": "apt",
            "InstalledVersion": "2.6.1",
            "FixedVersion": "2.6.2",
            "Status": "affected",
            "Title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
            "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
            "Severity": "LOW",
            "CVSS": {
                "nvd": {
                    "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                    "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    "V2Score": 4.3,
                    "V3Score": 3.7,
                }
            },
            "PublishedDate": "2019-11-26T00:15:11.03Z",
            "LastModifiedDate": "2021-02-09T16:08:18.683Z",
            "References": ["https://security-tracker.debian.org/tracker/CVE-2011-3374"],
            "CweIDs": ["CWE-20"],
            "VendorIDs": ["Vendor-123"],
            "Layer": {"DiffID": "sha256:abc123"},
        }
    ]
    fake_json_data = {
        "Results": [
            {
                "Target": "debian:10",
                "Type": "debian",
                "Vulnerabilities": fake_vulnerabilities
            }
        ]
    }
    with patch("builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)), \
         patch("builtins.print") as mock_print:
        deserializator = TrivyDeserializator()
        deserializator.get_container_context_from_results("fake_scan.json")
        printed = [call[0][0] for call in mock_print.call_args_list]
        output = "\n".join(printed)
        assert "===== BEGIN CONTEXT OUTPUT =====" in output
        assert "CVE-2011-3374" in output
        assert "apt" in output
        assert "2.6.1" in output
        assert "2.6.2" in output
        assert "low" in output
        assert "affected" in output
        assert "debian:10" in output
        assert "debian" in output
        assert "2021-02-09T16:08:18.683Z" in output
        assert "It was found that apt-key in apt, all versions, do not correctly validate gpg keys" in output
        assert "Trivy" in output
        assert "https://security-tracker.debian.org/tracker/CVE-2011-3374" in output
        assert "sha256:abc123" in output
        assert "CWE-20" in output
        assert "Vendor-123" in output
        assert "===== END CONTEXT OUTPUT =====" in output