import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.defect_dojo.applications.component import (
    Component,
)
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


class TestComponent(unittest.TestCase):

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.applications.component.ComponentRestConsumer"
    )
    def test_get_components(self, mock_rest_consumer):
        mock_rest_consumer.return_value.get_component.return_value = "response"
        session = MagicMock()
        request = MagicMock()
        assert Component.get_component(session, request) == "response"

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.applications.component.ComponentRestConsumer"
    )
    def test_get_components_raises_api_error(self, mock_component_rest_consumer):
        mock_component_rest_consumer.return_value.get_component.side_effect = Exception(
            "error"
        )
        session = MagicMock()
        request = MagicMock()
        with self.assertRaises(Exception) as e:
            Component.get_component(session, request)
            assert str(e) == "error"

    @patch(
        "devsecops_engine_tools.engine_utilities.defect_dojo.applications.component.ComponentRestConsumer"
    )
    def test_create_component(self, mock_rest_consumer):
        mock_rest_consumer.return_value.post_component.return_value = "response"
        session = MagicMock()
        request = MagicMock()
        assert Component.create_component(session, request) == "response"

    @patch(
            "devsecops_engine_tools.engine_utilities.defect_dojo.applications.component.ComponentRestConsumer"
        )
    def test_create_components_raises_api_error(self, mock_component_rest_consumer):
        mock_component_rest_consumer.return_value.post_component.side_effect = Exception(
            "error"
        )
        session = MagicMock()
        request = MagicMock()
        with self.assertRaises(Exception) as e:
            Component.create_component(session, request)
            assert str(e) == "error"