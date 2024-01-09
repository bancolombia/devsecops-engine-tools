from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import (
    TrivyScan
)

from unittest.mock import patch, Mock, mock_open
import pytest

@pytest.fixture
def trivy_scan_instance():
    return TrivyScan()

def test_install_trivy_success(trivy_scan_instance):
    with patch('subprocess.run', return_value=Mock()) as mock_subprocess_run:
        trivy_scan_instance.install_trivy('0.48.1')
    
    mock_subprocess_run.assert_called() # Make sure subprocess.run has been called correctly
    assert mock_subprocess_run.call_count == 1, "subprocess no se ejecuta una vez (verificar)"

def test_run_tool_container_sca(trivy_scan_instance):
    mock_remoteconfig = {
        'TRIVY': {
            'TRIVY_VERSION': '0.48.1'
        },
        'REGEX_EXPRESSION_PROJECTS': '((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS[A-Z]{3})\\d+)'
    }
    mock_scan_image = [
        {
            'Repository': 'nu0429002_devsecops_test_debian',
            'Tag': 'latest'
        },
        {
            'Repository': 'nu0429002_devsecops_test',
            'Tag': 'latest'
        },
        {
            'Repository': 'Ubuntu',
            'Tag': 'latest'
        },
        {
            'Repository': 'Debian',
            'Tag': 'latest'
        },
        {
            'Repository': 'nu000000_test',
            'Tag': '1.2'
        },
    ]

    with patch('subprocess.run', return_value=Mock()) as mock_subprocess_run:
        with patch('builtins.open', mock_open()) as mock_file_open:
            result = trivy_scan_instance.run_tool_container_sca(mock_remoteconfig, 'token', mock_scan_image)

    # Subprocess
    mock_subprocess_run.assert_called() # Make sure subprocess.run has been called correctly
    assert mock_subprocess_run.call_count == 7, "el escaneo no se ejecuta solo tres veces (verificar)+(escaneo)*2"
    
    # Open file
    mock_file_open.assert_called() # Make sure that an attempt has been made to open the file
    assert mock_file_open.call_count == 9, "no se escribio en el archivo solo tres veces (Crear, leer y escribir)*escaneos"

    # Return
    assert isinstance(result, list) # Make sure that a list has been returned
    expected_result = ['nu0429002_devsecops_test_debian:latest_scan_result.json',
                       'nu0429002_devsecops_test:latest_scan_result.json',
                       'nu000000_test:1.2_scan_result.json']
    assert result == expected_result, "La lista resotrnada no es la esperada"