import requests
import re
import json
from unittest.mock import Mock
from devsecops_engine_tools.engine_utilities.settings import devsecops_engine_tools.engine_utilities_PATH
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager


def get_response(name_file: str):
    with open(f"{devsecops_engine_tools.engine_utilities_PATH}/defect_dojo/test/files/{name_file}", "r") as fp:
        data = json.load(fp)
        return data


def session_manager_get(status_code, response_json_file):
    # Mocks
    session_mock = Mock()
    response_mock_get = Mock()
    response_mock_get.status_code = status_code
    response_mock_get.json.return_value = get_response(response_json_file)
    # mock method get
    session_mock.get.return_value = response_mock_get
    mock_session_manager = Mock()
    mock_session_manager.token = "test123"
    mock_session_manager.host = "http://localhsot:800"
    mock_session_manager._instance = session_mock
    return mock_session_manager


def session_manager_post(status_code, mock_response):
    # mocke method post
    session_mock = Mock()
    response_mock_post = Mock()
    response_mock_post.status_code = status_code
    if re.search(r".+.json", str(mock_response)):
        response_mock_post.json.return_value = get_response(mock_response)
    else:
        response_mock_post.json.return_value = mock_response
    # mock method post
    session_mock.post.return_value = response_mock_post
    # instance session mock in atribute
    mock_session_manager = Mock()
    mock_session_manager.token = "test123"
    mock_session_manager.host = "http://localhsot:800"
    mock_session_manager._instance = session_mock
    return mock_session_manager
