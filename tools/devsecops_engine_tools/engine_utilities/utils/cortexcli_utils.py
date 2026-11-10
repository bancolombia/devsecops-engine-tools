import hashlib
import io
import os
import platform
import re
import tarfile
import zipfile

import requests


def download_cortexcli(version):
    version = version.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("CORTEX_CLI_VERSION must be a release version such as 0.37.0")
    system = platform.system().lower()
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower()
    )
    if system not in ("linux", "darwin", "windows") or architecture is None or (
        system == "windows" and architecture != "amd64"
    ):
        raise ValueError("Unsupported platform for cortexcli")
    binary_name = "cortexcli.exe" if system == "windows" else "cortexcli"
    directory = os.path.join(os.getcwd(), ".cortexcli", version, f"{system}-{architecture}")
    binary_path = os.path.join(directory, binary_name)
    if os.path.isfile(binary_path):
        return binary_path

    extension = "zip" if system == "windows" else "tar.gz"
    asset = f"cortexcli-v{version}-{system}-{architecture}.{extension}"
    release_url = f"https://github.com/PaloAltoNetworks/homebrew-cortexcli/releases/download/v{version}"
    response = requests.get(f"{release_url}/{asset}", timeout=60)
    response.raise_for_status()
    checksums = requests.get(f"{release_url}/SHA256SUMS", timeout=60)
    checksums.raise_for_status()
    expected = next(
        (parts[0] for line in checksums.text.splitlines()
         if len(parts := line.split()) == 2 and parts[1].lstrip("*") == asset),
        None,
    )
    if expected is None or hashlib.sha256(response.content).hexdigest() != expected:
        raise ValueError("Invalid cortexcli download checksum")

    archive_data = io.BytesIO(response.content)
    if system == "windows":
        with zipfile.ZipFile(archive_data) as archive:
            binary = archive.read(binary_name)
    else:
        with tarfile.open(fileobj=archive_data, mode="r:gz") as archive:
            member = archive.getmember(binary_name)
            if not member.isfile():
                raise ValueError("Invalid cortexcli executable in archive")
            with archive.extractfile(member) as executable:
                binary = executable.read()
    os.makedirs(directory, exist_ok=True)
    with open(binary_path, "wb") as executable:
        executable.write(binary)
    os.chmod(binary_path, 0o755)
    return binary_path