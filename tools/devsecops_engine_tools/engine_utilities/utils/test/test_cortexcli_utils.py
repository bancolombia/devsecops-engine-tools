import hashlib
import io
import tarfile
import zipfile
from unittest.mock import Mock, patch

import pytest

from devsecops_engine_tools.engine_utilities.utils.cortexcli_utils import download_cortexcli


@pytest.mark.parametrize("system,machine,extension,binary_name", [
    ("Linux", "x86_64", "tar.gz", "cortexcli"),
    ("Linux", "aarch64", "tar.gz", "cortexcli"),
    ("Darwin", "arm64", "tar.gz", "cortexcli"),
    ("Windows", "AMD64", "zip", "cortexcli.exe"),
])
def test_download_public_release(tmp_path, monkeypatch, system, machine, extension, binary_name):
    monkeypatch.chdir(tmp_path)
    content = io.BytesIO()
    if extension == "zip":
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr(binary_name, b"binary")
    else:
        with tarfile.open(fileobj=content, mode="w:gz") as archive:
            member = tarfile.TarInfo(binary_name)
            member.size = 6
            archive.addfile(member, io.BytesIO(b"binary"))
    payload = content.getvalue()
    architecture = "amd64" if machine.lower() in ("amd64", "x86_64") else "arm64"
    asset = f"cortexcli-v0.37.0-{system.lower()}-{architecture}.{extension}"
    with patch("platform.system", return_value=system), patch("platform.machine", return_value=machine), patch(
        "requests.get", side_effect=[
            Mock(content=payload),
            Mock(text=f"{hashlib.sha256(payload).hexdigest()}  {asset}\n"),
        ]
    ) as get:
        binary_path = download_cortexcli("v0.37.0")
        assert tmp_path.joinpath(binary_path).read_bytes() == b"binary"
        assert get.call_args_list[0].args[0].endswith(asset)
        assert get.call_args_list[0].kwargs == {"timeout": 60}
        assert download_cortexcli("0.37.0") == binary_path
        assert get.call_count == 2


def test_reject_invalid_checksum(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), patch(
        "requests.get", side_effect=[Mock(content=b"corrupted"), Mock(text="invalid  cortexcli-v0.37.0-linux-amd64.tar.gz")]
    ), pytest.raises(ValueError, match="checksum"):
        download_cortexcli("0.37.0")
    assert not list(tmp_path.rglob("cortexcli"))


@pytest.mark.parametrize("version", ["", "../0.37.0", "latest"])
def test_reject_invalid_version(version):
    with pytest.raises(ValueError, match="CORTEX_CLI_VERSION"):
        download_cortexcli(version)


def test_download_http_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), patch(
        "requests.get", return_value=Mock(raise_for_status=Mock(side_effect=RuntimeError("download failed")))
    ), pytest.raises(RuntimeError, match="download failed"):
        download_cortexcli("0.37.0")