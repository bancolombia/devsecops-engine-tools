import unittest
from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters import (
    HandleFilters,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import Report


class TestHandleFilters(unittest.TestCase):
    def setUp(self):
        self.remote_config = {"TAG_FILTER": ["tag3"]}
        self.findings = [
            Report(
                id="id2",
                date="21022024",
                status="stat2",
                where="path",
                tags=["tag1"],
                severity="sev1",
                active=True,
            ),
            Report(
                id="id2",
                date="21022024",
                status="stat2",
                where="path2",
                tags=["tag2"],
                severity="sev2",
                active=None,
            ),
            Report(
                id="id3",
                date="21022024",
                status="stat3",
                where="path3",
                tags=["tag3"],
                severity="sev3",
                active=True,
            ),
        ]
        self.handle_filters = HandleFilters(self.remote_config)

    def test_filter_by_tag(self):
        result = self.handle_filters.filter_by_tag(self.findings)

        assert result[0].tags == self.remote_config["TAG_FILTER"]

    def test_filter_by_status(self):
        result = self.handle_filters.filter_by_status(self.findings)

        assert len(result) == 2
