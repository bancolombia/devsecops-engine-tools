import unittest
from unittest.mock import MagicMock, patch
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement
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

    def test_get_where_with_package(self):
        # Arrange
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
        <dependency xmlns="http://example.com/schema">
            <identifiers>
                <package>
                    <id>pkg:example_namespace/example_name@1.0.0</id>
                </package>
            </identifiers>
        </dependency>"""

        # Act
        dependency = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        result = DependencyCheckDeserialize().get_where(dependency, {"ns": "http://example.com/schema"})

        # Assert
        self.assertEqual(result, "example_name:1.0.0")

    @patch("cpe.CPE")
    def test_get_where_with_cpe(self, MockCPE):
        # Arrange
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
        <dependency xmlns="http://example.com/schema">
            <identifiers>
                <identifier type="cpe">
                    <name>cpe:/a:vendor:product:1.0.0</name>
                </identifier>
            </identifiers>
        </dependency>"""
        
        MockCPE.return_value.get_vendor.return_value = ["vendor"]
        MockCPE.return_value.get_product.return_value = ["product"]
        MockCPE.return_value.get_version.return_value = ["1.0.0"]

        # Act
        dependency = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        result = DependencyCheckDeserialize().get_where(dependency, {"ns": "http://example.com/schema"})

        # Assert
        self.assertEqual(result, "vendor:product:1.0.0")

    def test_get_where_with_maven(self):
        # Arrange
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
        <dependency xmlns="http://example.com/schema">
            <identifiers>
                <identifier type="maven">
                    <name>group:artifact:1.0.0</name>
                </identifier>
            </identifiers>
        </dependency>"""

        # Act
        dependency = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        result = DependencyCheckDeserialize().get_where(dependency, {"ns": "http://example.com/schema"})

        # Assert
        self.assertEqual(result, ("group:artifact:1.0.0"))

    def test_get_where_without_identifiers(self):
        # Arrange
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
        <dependency xmlns="http://example.com/schema">test</dependency>"""

        # Act
        dependency = ET.ElementTree(ET.fromstring(xml_content)).getroot()
        result = DependencyCheckDeserialize().get_where(dependency, {"ns": "http://example.com/schema"})

        # Assert
        self.assertEqual(result, "")