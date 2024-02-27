import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from engine_utilities.defect_dojo.test.files.get_response import (
    get_response,
    session_manager_post,
    session_manager_get,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.finding import FindingRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.finding import Finding, FindingList


def test_get_finding_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="finding_list.json")
    rest_finding = FindingRestConsumer(session=session_mock)
    finding_obj = rest_finding.get(request={"unique_id_from_tool": "id_finding"})
    # Verificar el resultado
    assert isinstance(finding_obj, FindingList)
    assert finding_obj.count == 2
    assert isinstance(finding_obj.results, list)
    assert finding_obj.results[0].id == 1
    assert finding_obj.results[0].title == "title finding"
    assert finding_obj.results[0].description == "ID: arn:aws:securityhub/aws-foundational-security"
    assert finding_obj.results[0].unique_id_from_tool == "arn:aws:securityhub"


def test_get_finding_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="finding_list.json")
    rest_finding = FindingRestConsumer(session=session_mock)
    with pytest.raises(ApiError):
        rest_finding.get({"unique_id_from_tool": "id_finding"})


def test_close_finding_info_sucessfull():
    session_mock = session_manager_post(
        status_code=200,
        mock_response={
            "is_mitigated": True,
            "mitigated": "2023-10-08T21:07:16.236881Z",
            "false_p": False,
            "out_of_scope": False,
            "duplicate": False,
        },
    )

    rest_finding = FindingRestConsumer(session=session_mock)
    response = rest_finding.close(request={"unique_id_from_tool": "id_finding"}, id=1)
    response = response.json()
    assert isinstance(response, dict)
    assert response.get("is_mitigated") == True
    assert response.get("mitigated") == "2023-10-08T21:07:16.236881Z"


def test_post_finding_info_failure():
    session_mock = session_manager_post(
        status_code=500,
        mock_response={
            "is_mitigated": True,
            "mitigated": "2023-10-08T21:07:16.236881Z",
            "false_p": False,
            "out_of_scope": False,
            "duplicate": False,
        },
    )

    rest_finding = FindingRestConsumer(session=session_mock)
    with pytest.raises(ApiError):
        rest_finding.close(request={"unique_id_from_tool": "id_finding"}, id=1)
