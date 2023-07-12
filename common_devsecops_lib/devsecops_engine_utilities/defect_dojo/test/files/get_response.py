import json
from unittest.mock import Mock
from devsecops_engine_utilities.settings import DEVSECOPS_ENGINE_UTILITIES_PATH


def get_response(name_file: str):
    with open(f"{DEVSECOPS_ENGINE_UTILITIES_PATH}/defect_dojo/test/files/{name_file}", "r") as fp:
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
    return session_mock


def session_manager_post(status_code, response_json_file):
    # mocke method post
    session_mock = Mock()
    response_mock_post = Mock()
    response_mock_post.status_code = status_code
    response_mock_post.json.return_value = get_response(response_json_file)
    # mock method post
    session_mock.post.return_value = response_mock_post
    return session_mock
