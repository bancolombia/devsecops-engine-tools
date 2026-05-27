from abc import ABCMeta, abstractmethod


class ToolGateway(metaclass=ABCMeta):
    @abstractmethod
    def run_tool_license_sca(
        self,
        remote_config,
        dict_args,
        exclusions,
        pipeline_name,
        to_scan,
        sbom_path,
        image_to_scan,
        secret_tool,
        **kwargs,
    ) -> str:
        "run tool license sca"
