import os
import base64
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from devsecops_engine_tools.engine_sca.engine_function.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import (  # noqa: E501
    PrismaCloudManagerScan,
)


class TestPrismaCloudManagerScan(unittest.TestCase):
    def setUp(self):
        # tmp dir para archivos simulados (.zip / twistcli)
        self.tmpdir = tempfile.mkdtemp(prefix="ef_prisma_")
        # instancia del sujeto de pruebas
        self.sut = PrismaCloudManagerScan(tool_run=MagicMock(), dict_args={"folder_path": self.tmpdir})
        # Config remota simulada con claves esperadas por la implementación actual
        self.remoteconfig = {
            "PRISMA_CLOUD": {
                "PRISMA_CONSOLE_URL": "https://console.example",
                "PRISMA_ACCESS_KEY": "AK_xxx",
                "PRISMA_API_VERSION": "v1",
                "TWISTCLI_PATH": "twistcli.exe",  # se antepone os.getcwd()
            }
        }

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ----------------------------
    # download_twistcli (util/alias con clave combinada)
    # ----------------------------
    @patch("devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils.os.chmod")  # noqa: E501
    @patch("devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils.requests.get")  # noqa: E501
    def test_download_twistcli_success(self, mock_get, mock_chmod):
        """
        Valida que la descarga llame al util con Authorization: Basic <base64(AK:SK)>
        y escriba el binario en disco.
        """
        file_path = os.path.join(self.tmpdir, "twistcli.exe")

        # Simula respuesta OK
        resp = MagicMock()
        resp.content = b"BIN"
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp

        # Clave combinada (compat con firma del util/alias): "ACCESS:SECRET"
        prisma_key = "AK:SK"

        # Invoca (posicional) para no depender de nombres de kwargs
        ret = self.sut.download_twistcli(
            file_path,
            prisma_key,
            self.remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            self.remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
        )

        self.assertEqual(ret, 0)

        base_url = f"{self.remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL']}/api/{self.remoteconfig['PRISMA_CLOUD']['PRISMA_API_VERSION']}/util"  # noqa: E501
        # La variante "auto" resuelve ruta por OS/arch, así que verificamos prefijo y header
        called_url = mock_get.call_args.args[0]
        self.assertTrue(called_url.startswith(base_url))

        called_headers = (mock_get.call_args.kwargs.get("headers")
                          if mock_get.call_args and mock_get.call_args.kwargs
                          else {}) or {}
        self.assertIn("Authorization", called_headers)
        b64 = base64.b64encode(prisma_key.encode()).decode()
        self.assertEqual(called_headers["Authorization"], f"Basic {b64}")

        mock_chmod.assert_called_once()
        resp.raise_for_status.assert_called_once()
        # Se debe haber escrito el archivo
        self.assertTrue(os.path.exists(file_path))

    @patch("devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils.requests.get")  # noqa: E501
    def test_download_twistcli_failure(self, mock_get):
        """
        Simula error HTTP y valida que se lance ValueError desde el util/alias.
        """
        file_path = os.path.join(self.tmpdir, "twistcli.exe")
        prisma_key = "AK:SK"

        # Simula HTTP error
        resp = MagicMock()
        resp.raise_for_status.side_effect = Exception("HTTP 403")
        mock_get.return_value = resp

        with self.assertRaises(ValueError):
            self.sut.download_twistcli(
                file_path,
                prisma_key,
                self.remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                self.remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
            )

    # ----------------------------
    # run_tool_function_sca
    # ----------------------------
    @patch("builtins.print")
    def test_run_tool_function_sca_skip_true_returns_0(self, mock_print):
        """
        Escenario actual: aun con token_engine_container=None,
        se intenta descargar twistcli y se invoca _scan_function.
        Hacemos que _scan_function retorne 0 para que el resultado final sea 0.
        """
        with patch.object(self.sut, "download_twistcli") as m_dl, \
            patch.object(self.sut, "_scan_function") as m_scan:
            m_scan.return_value = 0
            ret = self.sut.run_tool_function_sca(
                remoteconfig=self.remoteconfig,
                secret_tool=None,
                token_engine_container=None,
            )

        self.assertEqual(ret, 0)
        mock_print.assert_not_called()   # el flujo actual no imprime en este caso
        m_dl.assert_called_once()        # ⬅️ se descarga twistcli en el camino actual
        m_scan.assert_called_once()      # ⬅️ y se ejecuta el “scan” (mockeado a 0)

    def test_run_tool_function_sca_downloads_if_missing_and_scans(self):
        """
        Si el binario no existe, debe descargarse (wrapper/alias) y luego escanear.
        """
        # Aseguramos que el twistcli no exista
        twistcli_abs = os.path.join(os.getcwd(), self.remoteconfig["PRISMA_CLOUD"]["TWISTCLI_PATH"])
        try:
            if os.path.exists(twistcli_abs):
                os.remove(twistcli_abs)
        except Exception:
            pass

        with patch.object(self.sut, "download_twistcli", return_value=0) as m_dl, \
             patch.object(self.sut, "_scan_function", return_value={"ok": True}) as m_scan:
            ret = self.sut.run_tool_function_sca(
                remoteconfig=self.remoteconfig,
                secret_tool=None,
                token_engine_container="AK:SK",
            )
            self.assertEqual(ret, {"ok": True})
            m_dl.assert_called_once()
            # Verifica que _scan_function haya sido llamado con el path completo
            m_scan.assert_called()
            args, kwargs = m_scan.call_args
            self.assertEqual(args[0], twistcli_abs)  # file_path

    @patch("devsecops_engine_tools.engine_sca.engine_function.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists")  # noqa: E501
    @patch("devsecops_engine_tools.engine_sca.engine_function.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.getcwd")  # noqa: E501
    def test_run_tool_function_sca_scan_raises_propagates(self, mock_getcwd, mock_exists):
        """
        Current behavior: run_tool_function_sca does NOT swallow exceptions raised by the scan routine.
        Therefore this test must expect the exception to propagate.
        """
        mock_getcwd.return_value = self.tmpdir
        mock_exists.return_value = True  # twistcli already present, no download

        # Make the scan routine raise (module currently calls _scan_function)
        with patch.object(self.sut, "_scan_function", side_effect=RuntimeError("boom")) as m_scan:
            with self.assertRaises(RuntimeError):
                self.sut.run_tool_function_sca(
                    remoteconfig=self.remoteconfig,
                    secret_tool=None,
                    token_engine_container="AK:SK",
                )
            m_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
