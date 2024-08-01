from devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan import (
    runner_engine_container,
)

from unittest.mock import patch


def test_init_engine_container():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.init_engine_sca_rm"
    ) as mock_init_engine_sca_rm:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "PRISMA"

        result = runner_engine_container(dict_args, tool, token, None)

        mock_init_engine_sca_rm.assert_any_call
