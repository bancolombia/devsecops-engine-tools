import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import Report


class TestBreakBuild(unittest.TestCase):
    @patch(
        "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.PrinterTableGateway"
    )
    def test_process_no_report(self, mock_print_table):
        report_list = [Report()]

        BreakBuild(MagicMock(), mock_print_table, MagicMock()).process(report_list)

        mock_print_table.print_table_report.assert_called_with(report_list)

    @patch(
        "devsecops_engine_tools.engine_risk.src.domain.usecases.break_build.DevopsPlatformGateway"
    )
    def test_process_print_with_report(self, mock_devops_platform):
        report_list = []

        BreakBuild(mock_devops_platform, MagicMock(), MagicMock()).process(report_list)

        mock_devops_platform.message.assert_called_with(
            "succeeded", "There are no vulnerabilities"
        )
