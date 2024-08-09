import unittest
from unittest.mock import patch, mock_open
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_scan_file_maker import (
    BearerScanFileMaker,
)

class TestBearerScanFileMaker(unittest.TestCase):
    
    @patch(
        "builtins.open"
    )
    @patch(
        "json.load"
    )
    def test_add_vulnerabilities(self, mock_json_load, mock_open):
        # Arrange
        mock_json_load.return_value = {
            "high": [
                {"vul_id1": "test1"},
                {"vul_id2": "test2"}
            ],
            "medium": [
                {"vul_id3": "test3"}
            ],
            "low": [
                {"vul_id4": "test4"}
            ],
            "critical": [
                {"vul_id5": "test5"}
            ]
        }
        scan_file_maker = BearerScanFileMaker()
        
        # Act
        scan_file_maker.add_vulnerabilities("test_path.json")
        
        # Assert
        mock_open.assert_called_once_with("test_path.json", encoding='utf-8')
        self.assertIn("high", scan_file_maker.vulnerabilities)
        self.assertIn("medium", scan_file_maker.vulnerabilities)
        self.assertIn("low", scan_file_maker.vulnerabilities)
        self.assertIn("critical", scan_file_maker.vulnerabilities)
        self.assertEqual(len(scan_file_maker.vulnerabilities["high"]), 2)
        self.assertEqual(len(scan_file_maker.vulnerabilities["medium"]), 1)
        self.assertEqual(len(scan_file_maker.vulnerabilities["low"]), 1)
        self.assertEqual(len(scan_file_maker.vulnerabilities["critical"]), 1)
        self.assertEqual(scan_file_maker.vulnerabilities["high"][0]["vul_id1"], "test1")
        self.assertEqual(scan_file_maker.vulnerabilities["high"][1]["vul_id2"], "test2")
        self.assertEqual(scan_file_maker.vulnerabilities["medium"][0]["vul_id3"], "test3")
        self.assertEqual(scan_file_maker.vulnerabilities["low"][0]["vul_id4"], "test4")
        self.assertEqual(scan_file_maker.vulnerabilities["critical"][0]["vul_id5"], "test5")

    @patch(
        "builtins.open", 
        new_callable=mock_open
    )
    @patch(
        "json.dump"
    )
    def test_make_scan_file(self, mock_json_dump, mock_open):
        # Arrange
        scan_file_maker = BearerScanFileMaker()
        scan_file_maker.vulnerabilities = {
            "high": [
                {"id": "vul1"}, 
                {"id": "vul2"}
            ],
            "medium": [
                {"id": "vul3"}
            ]
        }
        
        # Act
        result_path = scan_file_maker.make_scan_file("/agent/work/folder")
        
        # Assert
        mock_open.assert_called_once_with("/agent/work/folder/bearer-scan-vul-man.json", "w")
        mock_json_dump.assert_called_once_with(scan_file_maker.vulnerabilities, mock_open())
        self.assertEqual(result_path, "/agent/work/folder/bearer-scan-vul-man.json")
        