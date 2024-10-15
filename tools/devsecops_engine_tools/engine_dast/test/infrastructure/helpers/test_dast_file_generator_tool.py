import unittest
from unittest.mock import patch, mock_open, call
import json

# Importa la función a probar
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool import generate_file_from_tool, update_field

class TestGenerateFileFromTool(unittest.TestCase):
    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool.open", new_callable=mock_open)  # Simula 'open'
    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool.os.path.abspath")  # Simula 'os.path.abspath'
    def test_generate_file_from_tool_nuclei(self, mock_abspath, mock_open):
        # Datos de entrada simulados
        tool = "nuclei"
        result_list = [
            {
                "results": {
                    "failed_checks": [
                        {"check_id": "id1", "severity": "high"},
                        {"check_id": "id2", "severity": "medium"},
                    ]
                },
                "summary": {
                    "passed": 5,
                    "failed": 2,
                    "skipped": 1,
                    "parsing_errors": 0,
                    "resource_count": 10,
                    "version": "2.4.1",
                }
            },
            {
                "results": {
                    "failed_checks": [
                        {"check_id": "id3", "severity": "low"},
                    ]
                },
                "summary": {
                    "passed": 2,
                    "failed": 1,
                    "skipped": 0,
                    "parsing_errors": 0,
                    "resource_count": 5,
                    "version": "2.4.1",
                }
            }
        ]
        rules_doc = {
            "id1": {"severity": "critical"},
            "id2": {"severity": "high"},
            "id3": {"severity": "low"},
        }

        # Valores de retorno simulados
        mock_abspath.return_value = "/mocked/path/results.json"

        # Llamada a la función
        result = generate_file_from_tool(tool, result_list, rules_doc)

        # Verificación del nombre de archivo devuelto
        self.assertEqual(result, "/mocked/path/results.json")

        # Verifica que 'open' se llame con el nombre de archivo correcto
        mock_open.assert_called_once_with("results.json", "w")
        
        # Obtener la instancia del archivo simulado
        handle = mock_open()
        handle.write.assert_called()  # Verifica que write se haya llamado
