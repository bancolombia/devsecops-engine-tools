import unittest
import json
from unittest.mock import mock_open, patch
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import Component


class TestGetListComponent(unittest.TestCase):
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps(
            {
                "components": [
                    {"group": "group1", "name": "component1", "version": "1.0.0"},
                    {"group": "group2", "name": "component2", "version": "2.0.0"},
                    {"group": "group3", "name": "component3", "version": "UNKNOWN"},
                ]
            }
        ),
    )
    def test_get_list_component_cyclonedx(self, mock_file):
        result_sbom = "dummy_path"
        format = "cyclonedx"
        expected_components = [
            Component("group1_component1", "1.0.0"),
            Component("group2_component2", "2.0.0"),
        ]

        components = get_list_component(result_sbom, format)

        self.assertEqual(components, expected_components)
        mock_file.assert_called_once_with(result_sbom, "rb")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"components": []}),
    )
    def test_get_list_component_empty(self, mock_file):
        result_sbom = "dummy_path"
        format = "cyclonedx"
        expected_components = []

        components = get_list_component(result_sbom, format)

        self.assertEqual(components, expected_components)
        mock_file.assert_called_once_with(result_sbom, "rb")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps(
            {
                "components": [
                    {"name": "component1", "version": "1.0.0"},
                    {"name": "component2", "version": "2.0.0"},
                ]
            }
        ),
    )
    def test_get_list_component_non_cyclonedx_format(self, mock_file):
        result_sbom = "dummy_path"
        format = "other_format"
        expected_components = []

        components = get_list_component(result_sbom, format)

        self.assertEqual(components, expected_components)
        mock_file.assert_called_once_with(result_sbom, "rb")
