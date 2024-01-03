import unittest
from unittest.mock import patch, MagicMock
from tools.devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_nuclei import (
    start_process,
)


class TestStartProcess(unittest.TestCase):
    @patch(
        "tools.devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_nuclei.nuclei"
    )
    @patch(
        "tools.devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.entry_point_nuclei.NucleiProcess"
    )
    def test_start_process_calls_nuclei_scan(self, mock_nuclei_process, mock_nuclei):
        # Arrange
        url = "https://example.com"
        template = "template.yaml"
        json_data = {"scan": [{"info": {"host": "example.com"}}]}
        mock_nuclei.return_value = json_data
        mock_nuclei_process_instance = MagicMock()
        mock_nuclei_process.return_value = mock_nuclei_process_instance

        # Act
        start_process(url, template)

        # Assert
        mock_nuclei.assert_called_once_with(url, template)
        mock_nuclei_process.assert_called_once_with(json_data["scan"])
        mock_nuclei_process_instance.get_result_scans.assert_called_once()
        mock_nuclei_process_instance.get_list_vulnerabilities.assert_called_once()
        mock_nuclei_process_instance.print_table.assert_called_once()
