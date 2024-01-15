import unittest
from unittest.mock import patch, MagicMock
from tools.devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_deserealizer import (
    NucleiProcess,
)


class TestNucleiProcess(unittest.TestCase):
    def setUp(self):
        self.scan_data = [
            {
                "template-url": "https://example.com/template1",
                "template-id": "template1",
                "info": {
                    "classification": {
                        "cve-id": "CVE-2021-1234",
                        "cwe-id": "CWE-1234",
                        "cvss-score": 7.5,
                    },
                    "description": "A description",
                    "severity": "high",
                    "remediation": "Remediation steps",
                },
                "type": "http",
                "matched-at": "http://example.com",
                "timestamp": "2021-10-01T00:00:00Z",
                "host": "example.com",
            },
            {
                "template-url": "https://example.com/template2",
                "template-id": "template2",
                "info": {
                    "name": "DNS vulnerability",
                    "description": "A DNS vulnerability",
                    "severity": "medium",
                    "remediation": "Remediation steps",
                },
                "type": "dns",
                "matched-at": "example.com",
                "timestamp": "2021-10-01T00:00:00Z",
                "host": "example.com",
            },
        ]
        self.scan = MagicMock()
        self.scan.data = self.scan_data
        self.nuclei_process = NucleiProcess(self.scan)

    def test_get_template(self):
        data = {
            "template-url": "https://example.com/template1",
            "template-id": "template1",
            "info": {
                "classification": {
                    "cve-id": "CVE-2021-1234",
                    "cwe-id": "CWE-1234",
                    "cvss-score": 7.5,
                },
                "description": "A description",
                "severity": "high",
                "remediation": "Remediation steps",
            },
            "type": "http",
            "matched-at": "http://example.com",
            "timestamp": "2021-10-01T00:00:00Z",
            "host": "example.com",
        }
        expected_template = {
            "url": "https://example.com/template1",
            "id": "template1",
            "info": {
                "classification": {
                    "cve-id": "CVE-2021-1234",
                    "cwe-id": "CWE-1234",
                    "cvss-score": 7.5,
                },
                "description": "A description",
                "category": "http",
            },
        }
        template = self.nuclei_process.get_template(data)
        self.assertEqual(template.__dict__, expected_template)

    def test_vulnerability_matcher_cve(self):
        data = {
            "template-url": "https://example.com/template1",
            "template-id": "template1",
            "info": {
                "classification": {
                    "cve-id": "CVE-2021-1234",
                    "cwe-id": "CWE-1234",
                    "cvss-score": 7.5,
                },
                "description": "A description",
                "severity": "high",
                "remediation": "Remediation steps",
            },
            "type": "http",
            "matched-at": "http://example.com",
            "timestamp": "2021-10-01T00:00:00Z",
            "host": "example.com",
        }
        expected_vulnerability = {
            "id": "CVE-2021-1234",
            "cwe_id": "CWE-1234",
            "cvss": 7.5,
            "where_vulnerability": "http://example.com",
            "description": "A description",
            "severity": "high",
            "identification_date": "2021-10-01T00:00:00Z",
            "type_vulnerability": "http",
            "requirements": "Remediation steps",
            "tool": "Engine DAST",
            "is_excluded": False,
        }
        vulnerability = self.nuclei_process.vulnerability_matcher(data)
        self.assertEqual(vulnerability.__dict__, expected_vulnerability)

    def test_vulnerability_matcher_dns(self):
        data = {
            "template-url": "https://example.com/template2",
            "template-id": "template2",
            "info": {
                "name": "DNS vulnerability",
                "description": "A DNS vulnerability",
                "severity": "medium",
                "remediation": "Remediation steps",
            },
            "type": "dns",
            "matched-at": "example.com",
            "timestamp": "2021-10-01T00:00:00Z",
            "host": "example.com",
        }
        expected_vulnerability = {
            "id": "DNS vulnerability",
            "cwe_id": None,
            "cvss": None,
            "where_vulnerability": "example.com",
            "description": "A DNS vulnerability",
            "severity": "medium",
            "identification_date": "2021-10-01T00:00:00Z",
            "type_vulnerability": "dns",
            "requirements": "Remediation steps",
            "tool": "Engine DAST",
            "is_excluded": False,
        }
        vulnerability = self.nuclei_process.vulnerability_matcher(data)
        self.assertEqual(vulnerability.__dict__, expected_vulnerability)

    def test_check_dns(self):
        data = {
            "template-url": "https://example.com/template2",
            "template-id": "template2",
            "info": {
                "name": "DNS vulnerability",
                "description": "A DNS vulnerability",
                "severity": "medium",
                "remediation": "Remediation steps",
            },
            "type": "dns",
            "matched-at": "example.com",
            "timestamp": "2021-10-01T00:00:00Z",
            "host": "example.com",
        }
        expected_vulnerability = {
            "id": "DNS vulnerability",
            "cwe_id": None,
            "cvss": None,
            "where_vulnerability": "example.com",
            "description": "A DNS vulnerability",
            "severity": "medium",
            "identification_date": "2021-10-01T00:00:00Z",
            "type_vulnerability": "dns",
            "requirements": "Remediation steps",
            "tool": "Engine DAST",
            "is_excluded": False,
        }
        vulnerability = self.nuclei_process.check_dns(data)
        self.assertEqual(vulnerability.__dict__, expected_vulnerability)

    def test_check_ssl(self):
        data = {
            "template-url": "https://example.com/template2",
            "template-id": "template2",
            "info": {
                "name": "SSL vulnerability",
                "description": "An SSL vulnerability",
                "severity": "high",
                "remediation": "Remediation steps",
            },
            "type": "ssl",
            "matched-at": "example.com",
            "timestamp": "2021-10-01T00:00:00Z",
            "host": "example.com",
        }
        expected_vulnerability = {
            "id": "SSL vulnerability",
            "cwe_id": None,
            "cvss": None,
            "where_vulnerability": "example.com",
            "description": "An SSL vulnerability",
            "severity": "high",
            "identification_date": "2021-10-01T00:00:00Z",
            "type_vulnerability": "ssl",
            "requirements": "Remediation steps",
            "tool": "Engine DAST",
            "is_excluded": False,
        }
        vulnerability = self.nuclei_process.check_ssl(data)
        self.assertEqual(vulnerability.__dict__, expected_vulnerability)

    def test_get_result_scans(self):
        expected_result_scans = [
            {
                "template": {
                    "url": "https://example.com/template1",
                    "id": "template1",
                    "info": {
                        "classification": {
                            "cve-id": "CVE-2021-1234",
                            "cwe-id": "CWE-1234",
                            "cvss-score": 7.5,
                        },
                        "description": "A description",
                        "category": "http",
                    },
                },
                "target": "example.com",
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-1234",
                        "cwe_id": "CWE-1234",
                        "cvss": 7.5,
                        "where_vulnerability": "http://example.com",
                        "description": "A description",
                        "severity": "high",
                        "identification_date": "2021-10-01T00:00:00Z",
                        "type_vulnerability": "http",
                        "requirements": "Remediation steps",
                        "tool": "Engine DAST",
                        "is_excluded": False,
                    }
                ],
            },
            {
                "template": {
                    "url": "https://example.com/template2",
                    "id": "template2",
                    "info": {
                        "name": "DNS vulnerability",
                        "description": "A DNS vulnerability",
                        "severity": "medium",
                        "remediation": "Remediation steps",
                    },
                },
                "target": "example.com",
                "vulnerabilities": [
                    {
                        "id": "DNS vulnerability",
                        "cwe_id": None,
                        "cvss": None,
                        "where_vulnerability": "example.com",
                        "description": "A DNS vulnerability",
                        "severity": "medium",
                        "identification_date": "2021-10-01T00:00:00Z",
                        "type_vulnerability": "dns",
                        "requirements": "Remediation steps",
                        "tool": "Engine DAST",
                        "is_excluded": False,
                    }
                ],
            },
        ]
        self.nuclei_process.get_result_scans()
        result_scans = [
            result_scan.__dict__ for result_scan in self.nuclei_process.resultScans
        ]
        self.assertEqual(result_scans, expected_result_scans)

    def test_get_list_vulnerabilities(self):
        expected_vulnerabilities = [
            {
                "id": "CVE-2021-1234",
                "cwe_id": "CWE-1234",
                "cvss": 7.5,
                "where_vulnerability": "http://example.com",
                "description": "A description",
                "severity": "high",
                "identification_date": "2021-10-01T00:00:00Z",
                "type_vulnerability": "http",
                "requirements": "Remediation steps",
                "tool": "Engine DAST",
                "is_excluded": False,
            },
            {
                "id": "DNS vulnerability",
                "cwe_id": None,
                "cvss": None,
                "where_vulnerability": "example.com",
                "description": "A DNS vulnerability",
                "severity": "medium",
                "identification_date": "2021-10-01T00:00:00Z",
                "type_vulnerability": "dns",
                "requirements": "Remediation steps",
                "tool": "Engine DAST",
                "is_excluded": False,
            },
        ]
        vulnerabilities = [
            vulnerability.__dict__
            for vulnerability in self.nuclei_process.get_list_vulnerabilities()
        ]
        self.assertEqual(vulnerabilities, expected_vulnerabilities)

    @patch(
        "tools.devsecops_engine_tools.engine_dast.src.domain.usecases.nuclei_process.PrettyTable"
    )
    def test_print_table(self, mock_pretty_table):
        vulnerabilities_without_exclusions_list = [
            {
                "id": "CVE-2021-1234",
                "cwe_id": "CWE-1234",
                "cvss": 7.5,
                "where_vulnerability": "http://example.com",
                "description": "A description",
                "severity": "high",
                "identification_date": "2021-10-01T00:00:00Z",
                "type_vulnerability": "http",
                "requirements": "Remediation steps",
                "tool": "Engine DAST",
                "is_excluded": False,
            },
            {
                "id": "DNS vulnerability",
                "cwe_id": None,
                "cvss": None,
                "where_vulnerability": "example.com",
                "description": "A DNS vulnerability",
                "severity": "medium",
                "identification_date": "2021-10-01T00:00:00Z",
                "type_vulnerability": "dns",
                "requirements": "Remediation steps",
                "tool": "Engine DAST",
                "is_excluded": False,
            },
        ]
        self.nuclei_process.print_table(vulnerabilities_without_exclusions_list)
        mock_pretty_table.assert_called_once_with(
            ["Severity", "ID", "Description", "Where"]
        )
        mock_pretty_table.return_value.add_row.assert_any_call(
            ["high", "CVE-2021-1234", "A description", "http://example.com"]
        )
        mock_pretty_table.return_value.add_row.assert_any_call(
            ["medium", "DNS vulnerability", "A DNS vulnerability", "example.com"]
        )
        mock_pretty_table.return_value.align.__setitem__.assert_any_call(
            "Severity", "l"
        )
        mock_pretty_table.return_value.align.__setitem__.assert_any_call(
            "Description", "l"
        )
        mock_pretty_table.return_value.align.__setitem__.assert_any_call("ID", "l")
        mock_pretty_table.return_value.align.__setitem__.assert_any_call("Where", "l")
        mock_pretty_table.return_value.set_style.assert_called_once_with("||")


if __name__ == "__main__":
    unittest.main()
