from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)

import re
import os


class FindMonoRepos:
    def __init__(
        self,
        tool_remote: DevopsPlatformGateway,
    ):
        self.tool_remote = tool_remote

    def get_variable(self, variable):
        """
        Get variable.

        Returns:
            dict: Remote variable.
        """
        return self.tool_remote.get_variable(variable)

    def handle_find_mono_repo(self, pipeline_name):
        """
        Handle find mono repository dir.

        Return: String: Directory to scan.
        """
        current_dir = os.getcwd()
        pattern = "_MR_"
        if pattern in pipeline_name:
            mr_dir = pipeline_name.split(pattern)[1]
            mr_dir_path = os.path.join(current_dir, mr_dir)
            if os.path.isdir(mr_dir_path):
                return mr_dir_path

            for root, dirs, files in os.walk(current_dir):
                if mr_dir in dirs:
                    return os.path.join(root, mr_dir)

        return current_dir

    def process_find_mono_repo(self):
        """
        Process handle find mono repository dir.

        Return: String: Directory to scan.
        """
        return self.handle_find_mono_repo(
            self.get_variable("pipeline_name"),
        )
