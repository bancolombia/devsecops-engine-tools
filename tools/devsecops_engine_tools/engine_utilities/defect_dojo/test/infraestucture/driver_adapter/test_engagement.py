import pytest
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.cmdb import Cmdb
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.defect_dojo.test.files.get_response import (
    session_manager_post,
    session_manager_get,
    session_manager_patch,
    get_response,
)
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.engagement import EngagementRestConsumer
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.engagement import Engagement, EngagementList


def test_get_engagement_info_success():
    session_mock = session_manager_get(status_code=200, response_json_file="engagement_list.json")
    # Crear una instancia de CmdbRestConsumer con los mocks
    rest_engagement = EngagementRestConsumer(
        ImportScanRequest(),
        session_mock,
    )

    # Llamar al método bajo prueba
    engagement_obj = rest_engagement.get_engagements("NU0212001_test_engagement_name")

    # Verificar el resultado
    assert isinstance(engagement_obj, EngagementList)
    assert engagement_obj.count == 1
    assert isinstance(engagement_obj.results, list)
    assert engagement_obj.results[0].name == "NU0212001_test_engagement_name"


def test_get_engagement_info_failure():
    session_mock = session_manager_get(status_code=500, response_json_file="engagement_list.json")
    rest_engagement = EngagementRestConsumer(
        ImportScanRequest(),
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_engagement.get_engagements("NU0212001_test_engagement_name")


def test_post_engagement_info_sucessfull():
    session_mock = session_manager_post(status_code=201, mock_response="engagement.json")
    rest_engagement = EngagementRestConsumer(
        ImportScanRequest(),
        session_mock,
    )
    response = rest_engagement.post_engagement(ImportScanRequest(), product_id=195, tool_scm_configuration_id=2)
    assert response.id == 195


def test_post_engagement_info_failure():
    session_mock = session_manager_post(status_code=500, mock_response="engagement.json")
    rest_engagement = EngagementRestConsumer(
        ImportScanRequest(),
        session_mock,
    )
    with pytest.raises(ApiError):
        rest_engagement.post_engagement(ImportScanRequest(), product_id=195, tool_scm_configuration_id=2)


def test_patch_engagement_method_exists():
    """Verify the patch_engagement method exists on EngagementRestConsumer"""
    request = ImportScanRequest(
        engagement_name="test engagement",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    assert hasattr(consumer, "patch_engagement")
    assert callable(consumer.patch_engagement)

def test_patch_engagement_with_description_success():
    """Test successful patch_engagement with engagement_description"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        engagement_description="Updated description",
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    result = consumer.patch_engagement(request, engagement_id=1)
    
    assert result is not None
    assert isinstance(result, Engagement)
    assert result.id == 195  # From the test engagement.json file

def test_patch_engagement_empty_description_success():
    """Test successful patch_engagement with empty description"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        engagement_description="",
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    result = consumer.patch_engagement(request, engagement_id=1)
    
    assert result is not None
    assert isinstance(result, Engagement)

def test_patch_engagement_failure_400_status():
    """Test patch_engagement raises ApiError on 400 status"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
    )
    session_mock = session_manager_patch(status_code=400, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    with pytest.raises(ApiError):
        consumer.patch_engagement(request, engagement_id=1)

def test_patch_engagement_failure_500_status():
    """Test patch_engagement raises ApiError on 500 status"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
    )
    session_mock = session_manager_patch(status_code=500, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    with pytest.raises(ApiError):
        consumer.patch_engagement(request, engagement_id=1)

def test_patch_engagement_with_special_characters_in_description():
    """Test patch_engagement with special characters in description"""
    special_desc = 'Description with "quotes" and chars: <>&éñü'
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        engagement_description=special_desc,
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)
    
    result = consumer.patch_engagement(request, engagement_id=1)
    
    assert result is not None
    assert isinstance(result, Engagement)


def test_get_engagements_by_request_paginates_through_next_page():
    """Test get_engagements_by_request follows the 'next' link and merges results"""
    first_page = get_response("engagement_list.json")
    first_page = dict(first_page)
    first_page["next"] = "http://localhost:8000/api/v2/engagements/?page=2"

    second_page = get_response("engagement_list.json")
    second_page = dict(second_page)
    second_page["next"] = None
    second_page["results"] = [dict(second_page["results"][0])]
    second_page["results"][0]["id"] = 196
    second_page["results"][0]["name"] = "second_page_engagement"

    response_page_1 = Mock(status_code=200)
    response_page_1.json.return_value = first_page
    response_page_2 = Mock(status_code=200)
    response_page_2.json.return_value = second_page

    session_mock = Mock()
    session_mock.get.side_effect = [response_page_1, response_page_2]
    mock_session_manager = Mock()
    mock_session_manager._instance = session_mock

    rest_engagement = EngagementRestConsumer(ImportScanRequest(), mock_session_manager)
    engagements = rest_engagement.get_engagements("NU0212001_test_engagement_name")

    assert session_mock.get.call_count == 2
    assert len(engagements.results) == 2
    assert engagements.results[1].name == "second_page_engagement"


def test_get_engagements_by_request_raises_on_second_page_failure():
    """Test get_engagements_by_request raises ApiError when the paginated 'next' request fails"""
    first_page = get_response("engagement_list.json")
    first_page = dict(first_page)
    first_page["next"] = "http://localhost:8000/api/v2/engagements/?page=2"

    response_page_1 = Mock(status_code=200)
    response_page_1.json.return_value = first_page
    response_page_2 = Mock(status_code=500)
    response_page_2.json.return_value = {"detail": "server error"}

    session_mock = Mock()
    session_mock.get.side_effect = [response_page_1, response_page_2]
    mock_session_manager = Mock()
    mock_session_manager._instance = session_mock

    rest_engagement = EngagementRestConsumer(ImportScanRequest(), mock_session_manager)

    with pytest.raises(ApiError):
        rest_engagement.get_engagements("NU0212001_test_engagement_name")


def test_post_engagement_includes_source_code_management_uri():
    """Test post_engagement adds source_code_management_uri to the payload when present"""
    request = ImportScanRequest(
        engagement_name="test engagement",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        source_code_management_uri="https://github.com/org/repo",
    )
    session_mock = session_manager_post(status_code=201, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)

    response = consumer.post_engagement(request, product_id=195, tool_scm_configuration_id=None)

    assert response.id == 195
    _, kwargs = session_mock._instance.post.call_args
    assert '"source_code_management_uri": "https://github.com/org/repo"' in kwargs["data"]


def test_post_engagement_raises_api_error_on_unexpected_exception():
    """Test post_engagement wraps unexpected exceptions raised by the session in ApiError"""
    request = ImportScanRequest(
        engagement_name="test engagement",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
    )
    session_mock = Mock()
    session_mock.post.side_effect = ConnectionError("connection reset")
    mock_session_manager = Mock()
    mock_session_manager._instance = session_mock

    consumer = EngagementRestConsumer(request, mock_session_manager)

    with pytest.raises(ApiError):
        consumer.post_engagement(request, product_id=195, tool_scm_configuration_id=None)


def test_patch_engagement_includes_source_code_management_uri():
    """Test patch_engagement adds source_code_management_uri to the payload when present"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
        source_code_management_uri="https://github.com/org/repo",
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)

    result = consumer.patch_engagement(request, engagement_id=1)

    assert isinstance(result, Engagement)
    _, kwargs = session_mock._instance.patch.call_args
    assert '"source_code_management_uri": "https://github.com/org/repo"' in kwargs["data"]


def test_patch_engagement_includes_tool_scm_configuration_id():
    """Test patch_engagement adds source_code_management_server to the payload when tool_scm_configuration_id is present"""
    request = ImportScanRequest(
        engagement_name="test",
        token_defect_dojo="token123",
        host_defect_dojo="http://localhost:8000",
    )
    session_mock = session_manager_patch(status_code=200, mock_response="engagement.json")
    consumer = EngagementRestConsumer(request, session_mock)

    result = consumer.patch_engagement(request, engagement_id=1, tool_scm_configuration_id=7)

    assert isinstance(result, Engagement)
    _, kwargs = session_mock._instance.patch.call_args
    assert '"source_code_management_server": 7' in kwargs["data"]
