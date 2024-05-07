import pytest
import json
from unittest.mock import MagicMock, Mock
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.set_input_core import SetInputCore
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import (
    DeserializeConfigTool
    )


@pytest.fixture
def mock_tool_remote():
    return Mock(spec=DevopsPlatformGateway)


def test_get_exclusions(mock_tool_remote):
    exclusions_data = {
      "All": {
          "TRUFFLEHOG": [
          ]
      },
      "NU00001_Pruebas": {
        "TRUFFLEHOG": [
          {
              "id": "SECRET_SCANNING",
              "cve_id": "",
              "where": "azure_api/secretos_azure_api.txt",
              "create_date": "30042024",
              "expired_date": "undefined",
              "hu": "12345",
              "reason": "false_positive"
          }
        ]
      }
    }
    pipeline_name = "NU00001_Pruebas"
    tool = "TRUFFLEHOG"
    config_tool = MagicMock()

    # Inicializa una instancia de SetInputCore
    set_input_core = SetInputCore(mock_tool_remote, None, tool, config_tool)

    # Llama al método get_exclusions
    exclusions = set_input_core.get_exclusions(exclusions_data, pipeline_name, tool)

    # Verifica que se obtenga la exclusión esperada
    assert len(exclusions) == 1
    assert isinstance(exclusions[0], Exclusions)
    assert exclusions[0].id == "SECRET_SCANNING"
    assert exclusions[0].where == "azure_api/secretos_azure_api.txt"
    assert exclusions[0].create_date == "30042024"
    assert exclusions[0].expired_date == "undefined"
    assert exclusions[0].hu == "12345"
