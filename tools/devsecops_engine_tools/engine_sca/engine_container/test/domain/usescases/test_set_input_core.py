import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions

from devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.set_input_core import (
    SetInputCore,
)


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
                        "hu": "",
                        "source_images": ["base_image:latest", "another_image:tag"],
                    }
                ]
            },
            "repository_test": {
                "PRISMA": [
                    {
                        "id": "XRAY-N94",
                        "create_date": "24012023",
                        "expired_date": "31122023",
                        "hu": "",
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
                        "hu": "",
                    }
                ]
            },
        }
    pipeline_name = "repository_test"
    base_image = "base_image:latest"  

    
    set_input_core = SetInputCore(mock_tool_remote, None, pipeline_name, "PRISMA", "release")

    exclusions = set_input_core.get_exclusions(exclusions_data, pipeline_name, "PRISMA", base_image)

    # Verificar resultados
    assert len(exclusions) == 2  
    assert exclusions[0].id == "CVE-2023-5363"  
    assert exclusions[1].id == "XRAY-N94"  


def test_get_exclusions_for_specific_pipeline(mock_tool_remote):
    exclusions_data = {
        "pipeline_specific": {
            "PRISMA": [
                {
                    "id": "CVE-2024-1234",
                    "where": "pipeline_specific",
                    "create_date": "01012024",
                    "expired_date": "31122024",
                    "hu": "High",
                }
            ]
        }
    }
    pipeline_name = "pipeline_specific"
    base_image = "base_image:latest"  
    set_input_core = SetInputCore(
        mock_tool_remote, None, pipeline_name, "PRISMA", "release"
    )
    exclusions = set_input_core.get_exclusions(exclusions_data, pipeline_name, "PRISMA",base_image)

    assert len(exclusions) == 1
    assert exclusions[0].id == "CVE-2024-1234"
    assert exclusions[0].where == "pipeline_specific"
    assert exclusions[0].create_date == "01012024"
    assert exclusions[0].expired_date == "31122024"
    assert exclusions[0].hu == "High"


def test_get_exclusions_no_matching_exclusions(mock_tool_remote):
    exclusions_data = {
        "other_pipeline": {
            "PRISMA": [
                {
                    "id": "CVE-2024-5678",
                    "where": "other_pipeline",
                    "create_date": "02022024",
                    "expired_date": "30122024",
                    "hu": "Medium",
                }
            ]
        }
    }
    pipeline_name = "my_pipeline"
    base_image =  "base_image:latest"
    set_input_core = SetInputCore(
        mock_tool_remote, None, pipeline_name, "PRISMA", "release"
    )
    exclusions = set_input_core.get_exclusions(exclusions_data, pipeline_name, "PRISMA",base_image)

    assert len(exclusions) == 0
