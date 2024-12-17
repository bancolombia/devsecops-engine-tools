import unittest
import json
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component import (
    ComponentRestConsumer,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import Component
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from devsecops_engine_tools.engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.models.component import (
    ComponentList,
)


class TestComponentRestConsumer(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock(spec=SessionManager)
        self.session._token = "fake_token"
        self.session._host = "http://fakehost"
        self.session._instance = MagicMock()
        self.consumer = ComponentRestConsumer(self.session)

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component.VERIFY_CERTIFICATE",
        True,
    )
    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component.ComponentList"
    )
    def test_get_component_success(self, mock_component_list):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"components": []}
        self.session._instance.get.return_value = mock_response
        mock_component_list().from_dict.return_value = ComponentList()

        request = {"param": "value"}
        components = self.consumer.get_component(request)

        self.session._instance.get.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            params=request,
            verify=True,
        )
        mock_component_list().from_dict.assert_called_once_with({"components": []})
        self.assertIsInstance(components, ComponentList)

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component.logger"
    )
    def test_get_component_failure(self, mock_logger):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad Request"}
        self.session._instance.get.return_value = mock_response

        request = {"param": "value"}
        with self.assertRaises(ApiError):
            self.consumer.get_component(request)

        self.session._instance.get.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            params=request,
            verify=False,
        )
        mock_logger.error.assert_called_once_with({"error": "Bad Request"})

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component.logger"
    )
    def test_get_component_exception(self, mock_logger):
        self.session._instance.get.side_effect = Exception("Some error")

        request = {"param": "value"}
        with self.assertRaises(ApiError):
            self.consumer.get_component(request)

        self.session._instance.get.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            params=request,
            verify=False,
        )
        mock_logger.error.assert_not_called()

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.infraestructure.driver_adapters.component.VERIFY_CERTIFICATE",
        True,
    )
    def test_post_component_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 1, "name": "component"}
        self.session._instance.post.return_value = mock_response

        request = {"name": "component"}
        response = self.consumer.post_component(request)

        self.session._instance.post.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            data=json.dumps(request),
            verify=True,
        )
        self.assertEqual(response.name, "component")


    def test_post_component_failure(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad Request"}
        self.session._instance.post.return_value = mock_response

        request = {"name": "component"}
        with self.assertRaises(ApiError):
            self.consumer.post_component(request)

        self.session._instance.post.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            data=json.dumps(request),
            verify=False,
        )

    def test_post_component_exception(self):
        self.session._instance.post.side_effect = Exception("Some error")

        request = {"name": "component"}
        with self.assertRaises(ApiError):
            self.consumer.post_component(request)

        self.session._instance.post.assert_called_once_with(
            url="http://fakehost/api/v2/components/",
            headers={
                "Authorization": "Token fake_token",
                "Content-Type": "application/json",
            },
            data=json.dumps(request),
            verify=False,
        )

