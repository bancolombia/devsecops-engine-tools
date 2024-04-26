import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import DevopsPlatformGateway
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions

from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.set_input_core import SetInputCore  


@pytest.fixture
def mock_tool_remote():
    return Mock(spec=DevopsPlatformGateway)


def test_get_exclusions(mock_tool_remote):
    exclusions_data = {  
  "All": {
    "PRISMA": [
      {
        "id": "CVE-2023-5363",
        "where": "all",
        "create_date": "24012023",
        "expired_date": "22092023",
        "hu": ""
      }
    ]
  },
  "repository_test": {
    "PRISMA": [
      {
        "id": "XRAY-N94",
        "create_date": "24012023",
        "expired_date": "31122023",
        "hu": ""
      }
    ]
  },
  "12345_ProyectoEjemplo_RM": {
    "PRISMA": [
      {
        "id": "CVE-2023-6237",
        "cve_id": "CVE-2023-6237",
        "expired_date": "21092022",
        "create_date": "24012023",
        "hu": ""
      }
    ]
  }
}
    pipeline_name = "my_pipeline"
    config_tool = {"ENGINE_CONTAINER": {"TOOL": "PRISMA"}}

    # Inicializa una instancia de SetInputCore
    set_input_core = SetInputCore(mock_tool_remote, None, config_tool)

    # Llama al método get_exclusions
    exclusions = set_input_core.get_exclusions(exclusions_data, pipeline_name, config_tool)

    # Verifica que se obtenga la exclusión esperada
    assert len(exclusions) == 1
    assert isinstance(exclusions[0], Exclusions)
    assert exclusions[0].id == "CVE-2023-5363"
    assert exclusions[0].where == "all"
    assert exclusions[0].create_date == "24012023"
    assert exclusions[0].expired_date == "22092023"
    assert exclusions[0].hu == ""
