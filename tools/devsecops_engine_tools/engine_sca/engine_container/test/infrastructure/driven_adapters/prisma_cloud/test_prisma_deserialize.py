from unittest.mock import patch, mock_open
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_deserialize_output import PrismaDeserealizator

def test_get_container_context_from_results():
    sample_json = '''
    {
        "results": [
            {
                "name": "python:3.9",
                "distro": "debian",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-0001",
                        "severity": "high",
                        "packageName": "openssl",
                        "packageVersion": "1.1.1",
                        "description": "Test summary",
                        "cvss": 7.5,
                        "status": "open",
                        "discoveredDate": "2024-01-01T00:00:00+0000",
                        "publishedDate": "2024-01-01T00:00:00Z",
                        "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"
                    }
                ]
            }
        ]
    }
    '''
    with patch("builtins.open", mock_open(read_data=sample_json)), \
         patch("builtins.print") as mock_print:
        des = PrismaDeserealizator()
        des.get_container_context_from_results("fake_scan.json")

        printed = [call[0][0] for call in mock_print.call_args_list]
        assert any("===== BEGIN CONTEXT OUTPUT =====" in line for line in printed)
        assert any("CVE-2024-0001" in line for line in printed)
        assert any("openssl" in line for line in printed)
        assert any("1.1.1" in line for line in printed)
        assert any("high" in line for line in printed)
        assert any("open" in line for line in printed)
        assert any("7.5" in line for line in printed)
        assert any("python:3.9" in line for line in printed)
        assert any("debian" in line for line in printed)
        assert any("2024-01-01T00:00:00+0000" in line for line in printed)
        assert any("2024-01-01T00:00:00+00:00" in line for line in printed) or any("2024-01-01T00:00:00Z" in line for line in printed)
        assert any("Test summary" in line for line in printed)
        assert any("PrismaCloud" in line for line in printed)
        assert any("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001" in line for line in printed)
        assert any("===== END CONTEXT OUTPUT =====" in line for line in printed)