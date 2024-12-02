import unittest
from unittest.mock import MagicMock, patch
import xml.etree.ElementTree as ET
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.dependency_check.dependency_check_deserialize import (
    DependencyCheckDeserialize
)

class TestDependencyCheckDeserialize(unittest.TestCase):

    @patch(
        "xml.etree.ElementTree.parse"
    )
    def test_filter_vulnerabilities_by_confidence(self, mock_parse):
        # Arrange
        xml_content = """<?xml version='1.0' encoding='utf-8'?>
        <analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.4.0.xsd">
            <dependencies>
                <dependency>
                    <identifiers>
                        <vulnerabilityIds confidence="high" />
                    </identifiers>
                </dependency>
                <dependency>
                    <identifiers>
                        <vulnerabilityIds confidence="low" />
                    </identifiers>
                </dependency>
            </dependencies>
        </analysis>"""

        mock_parse.return_value = MagicMock()
        mock_parse.return_value.getroot.return_value = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        remote_config = {
            "DEPENDENCY_CHECK": {
                "VULNERABILITY_CONFIDENCE": ["high"]
            }
        }
        deserializer = DependencyCheckDeserialize()

        # Act
        dependencies, namespace = deserializer.filter_vulnerabilities_by_confidence("test_file.xml", remote_config)

        # Assert
        self.assertEqual(len(dependencies.findall('ns:dependency', namespace)), 1)
        self.assertEqual(dependencies.findall('ns:dependency', namespace)[0].find('ns:identifiers/ns:vulnerabilityIds', namespace).attrib["confidence"], "high")


    @patch(
        "xml.etree.ElementTree.parse"
    )
    def test_get_list_findings(self, mock_parse):
        # Arrange
        xml_content = """<?xml version='1.0' encoding='utf-8'?>
        <analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.4.0.xsd">
            <dependencies>
                <dependency>
                    <fileName>
                        file_to_scan.tar: example.jar
                    </fileName>
                    <identifiers>
                        <vulnerabilityIds confidence="high" />
                    </identifiers>
                    <vulnerabilities>
                        <vulnerability>
                            <name>CVE-2024-12345</name>
                            <severity>medium</severity>
                            <description>Test vulnerability description</description>
                        </vulnerability>
                    </vulnerabilities>
                </dependency>
            </dependencies>
        </analysis>"""

        mock_parse.return_value = MagicMock()
        mock_parse.return_value.getroot.return_value = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        remote_config = {
            "DEPENDENCY_CHECK": {
                "VULNERABILITY_CONFIDENCE": ["high", "medium"]
            }
        }
        deserializer = DependencyCheckDeserialize()

        # Act
        result = deserializer.get_list_findings("test_file.xml", remote_config)

        # Assert
        self.assertEqual(len(result), 1)
        finding = result[0]
        self.assertEqual(finding.id, "CVE-2024-12345")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.description, "Test vulnerability description")
        self.assertEqual(finding.where, "example.jar")
