from unittest.mock import patch
from devsecops_engine_tools.engine_risk.src.applications.runner_engine_risk import (
    runner_engine_risk,
)


@patch(
    "devsecops_engine_tools.engine_risk.src.applications.runner_engine_risk.init_engine_risk"
)
def test_runner_engine_risk(mock_init_engine_risk):
    devops_platform_gateway = "devops_platform_gateway"
    print_table_gateway = "print_table_gateway"
    dict_args = {"key": "value"}
    findings = []

    runner_engine_risk(
        dict_args,
        findings,
        devops_platform_gateway,
        print_table_gateway,
    )

    mock_init_engine_risk.assert_called_once()
