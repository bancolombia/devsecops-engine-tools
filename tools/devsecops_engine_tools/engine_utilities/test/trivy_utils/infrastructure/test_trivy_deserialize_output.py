from devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_deserialize_output import (
    TrivyDeserializator,
)

import pytest
from unittest.mock import mock_open, patch, MagicMock
import json


@pytest.fixture
def deserializator():
    return TrivyDeserializator()


@pytest.fixture
def fake_vulnerabilities():
    return [
        {
            "VulnerabilityID": "CVE-2011-3374",
            "PkgName": "apt",
            "InstalledVersion": "2.6.1",
            "Status": "affected",
            "FixedVersion": "2.7.0",
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
            "CweIDs": ["CWE-347"],
            "Layer": {"DiffID": "sha256:abc123"},
            "References": ["https://security.tracker.debian.org/tracker/CVE-2011-3374"]
        },
        {
            "VulnerabilityID": "CVE-2024-1234",
            "PkgName": "openssl",
            "InstalledVersion": "1.1.1",
            "Status": "fixed",
            "FixedVersion": "1.1.2",
            "Description": "Critical vulnerability in OpenSSL",
            "Severity": "CRITICAL",
            "CVSS": {
                "nvd": {
                    "V3Score": 9.8,
                }
            },
            "PublishedDate": "2024-01-15T10:30:00Z",
            "LastModifiedDate": "2024-01-20T12:00:00Z",
        }
    ]


def test_get_list_findings(deserializator, fake_vulnerabilities):
    images_scanned = "nu0429002_devsecops_test_debian_latest_scan_result.json"
    fake_json_data = {"Results": [{"Vulnerabilities": fake_vulnerabilities}]}
    
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)
    ):
        result = deserializator.get_list_findings(images_scanned, module="test-module")
        
        assert len(result) == 2
        assert result[0].id == "CVE-2011-3374"
        assert result[0].cvss == "3.7"
        assert result[0].where == "apt:2.6.1"
        assert result[0].severity == "low"
        assert result[0].requirements == "2.7.0"
        assert result[0].tool == "Trivy"
        assert result[0].module == "test-module"
        
        assert result[1].id == "CVE-2024-1234"
        assert result[1].cvss == "9.8"
        assert result[1].severity == "critical"


def test_get_list_findings_no_vulnerabilities(deserializator):
    images_scanned = "empty_scan_result.json"
    fake_json_data = {"Results": [{"Vulnerabilities": []}]}
    
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)
    ):
        result = deserializator.get_list_findings(images_scanned)
        assert len(result) == 0


def test_get_list_findings_no_published_date(deserializator):
    """Test that vulnerabilities without PublishedDate are filtered out"""
    images_scanned = "scan_result.json"
    fake_vulnerabilities = [
        {
            "VulnerabilityID": "CVE-NO-DATE",
            "PkgName": "test",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
            # No PublishedDate field
        }
    ]
    fake_json_data = {"Results": [{"Vulnerabilities": fake_vulnerabilities}]}
    
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)
    ):
        result = deserializator.get_list_findings(images_scanned)
        assert len(result) == 1


def test_get_container_context_from_results(deserializator, fake_vulnerabilities, capsys):
    images_scanned = "scan_result.json"
    fake_json_data = {
        "Results": [
            {
                "Target": "debian:latest",
                "Type": "debian",
                "Vulnerabilities": fake_vulnerabilities
            }
        ]
    }
    
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(fake_json_data)
    ):
        deserializator.get_container_context_from_results(images_scanned)
        
        captured = capsys.readouterr()
        assert "===== BEGIN CONTEXT OUTPUT =====" in captured.out
        assert "===== END CONTEXT OUTPUT =====" in captured.out
        assert "CVE-2011-3374" in captured.out
        assert "CVE-2024-1234" in captured.out
        assert "debian:latest" in captured.out


def test_get_cvss_v3_score_with_valid_data(deserializator):
    cvss_data = {
        "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
    }
    result = deserializator._get_cvss_v3_score(cvss_data)
    assert result == "7.5"


def test_get_cvss_v3_score_with_empty_data(deserializator):
    result = deserializator._get_cvss_v3_score(None)
    assert result == ""


def test_get_cvss_v3_score_no_v3_score(deserializator):
    cvss_data = {
        "nvd": {
            "V2Score": 5.0,
        }
    }
    result = deserializator._get_cvss_v3_score(cvss_data)
    assert result == ""


def test_get_cvss_v3_severity_low(deserializator):
    result = deserializator._get_cvss_v3_severity("3.5", "low")
    assert result == "low"


def test_get_cvss_v3_severity_medium(deserializator):
    result = deserializator._get_cvss_v3_severity("5.5", "medium")
    assert result == "medium"


def test_get_cvss_v3_severity_high(deserializator):
    result = deserializator._get_cvss_v3_severity("7.8", "high")
    assert result == "high"


def test_get_cvss_v3_severity_critical(deserializator):
    result = deserializator._get_cvss_v3_severity("9.5", "critical")
    assert result == "critical"


def test_get_cvss_v3_severity_no_score(deserializator):
    result = deserializator._get_cvss_v3_severity("", "medium")
    assert result == "medium"


def test_get_cvss_v3_severity_invalid_score(deserializator):
    result = deserializator._get_cvss_v3_severity("invalid", "low")
    assert result == "low"


def test_check_date_format_with_milliseconds(deserializator):
    vul = {"PublishedDate": "2019-11-26T00:15:11.03Z"}
    result = deserializator._check_date_format(vul)
    assert result == "2019-11-26T00:15:11.030000+00:00"


def test_check_date_format_without_milliseconds(deserializator):
    vul = {"PublishedDate": "2024-01-15T10:30:00Z"}
    result = deserializator._check_date_format(vul)
    assert result == "2024-01-15T10:30:00+00:00"
