from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.metrics_manager_gateway import (
    MetricsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_utilities.utils.logger_info import log_records
import datetime
import json
import os


class MetricsManager:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        metrics_manager_gateway: MetricsManagerGateway,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.metrics_manager_gateway = metrics_manager_gateway

    def process(
        self, config_tool: any, input_core: InputCore, dict_args: any, scan_result: any
    ):
        execution_id = self.devops_platform_gateway.get_variable("release_id") if input_core.stage_pipeline == "Release" else self.devops_platform_gateway.get_variable("build_execution_id")
        scope_pipeline = input_core.scope_pipeline
        base_directory = os.path.expanduser("/tmp/log_engine_tools")
        file_path = f"{base_directory}/{datetime.datetime.now()}_{scope_pipeline}_{execution_id}.json"
        base_directory_path = os.path.expanduser(base_directory)
        if not os.path.exists(base_directory_path):
            os.makedirs(base_directory_path)
        with open(
            file_path,
            "x",
        ) as file:
            body = {
                "id": execution_id,
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "component": scope_pipeline,
                "stage": input_core.stage_pipeline,
                "check_type": dict_args["tool"],
                "environment": dict_args["environment"],
                "events": log_records,
                "scan_result": scan_result
            }
            json.dump(body, file, indent=2)
        self.metrics_manager_gateway.send_metrics(
            config_tool, dict_args["tool"], file_path
        )
