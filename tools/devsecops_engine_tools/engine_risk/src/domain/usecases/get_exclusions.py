from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)


class GetExclusions:
    def __init__(
        self,
        devops_platform_gateway,
        dict_args,
        findings,
        risk_config,
        risk_exclusions,
        pipeline_name,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.dict_args = dict_args
        self.findings = findings
        self.risk_config = risk_config
        self.risk_exclusions = risk_exclusions
        self.pipeline_name = pipeline_name

    def process(self):
        core_config = self.devops_platform_gateway.get_remote_config(
            self.dict_args["remote_config_repo"], "engine_core/ConfigTool.json"
        )
        unique_tags = self._get_unique_tags()
        exclusions = []
        exclusions.extend(self._get_risk_exclusions())
        for key in self.risk_config["EXCLUSIONS_PATHS"].keys():
            if key in unique_tags:
                exclusions.extend(
                    self._get_exclusions_by_practice(
                        core_config, key, self.risk_config["EXCLUSIONS_PATHS"][key]
                    )
                )

        return exclusions

    def _get_risk_exclusions(self):
        return self._get_exclusions(self.risk_exclusions, "RISK")

    def _get_exclusions_by_practice(self, core_config, practice, path):
        exclusions_config = self.devops_platform_gateway.get_remote_config(
            self.dict_args["remote_config_repo"], path
        )
        tool = core_config[practice.upper()]["TOOL"]
        return self._get_exclusions(exclusions_config, tool)

    def _get_exclusions(self, config, key):
        exclusions = []
        for scope in ["All", self.pipeline_name]:
            if config.get(scope, None) and config[scope].get(key, None):
                exclusions.extend(
                    [
                        Exclusions(
                            **exclusion,
                        )
                        for exclusion in config[scope][key]
                    ]
                )
        return exclusions

    def _get_unique_tags(self):
        unique_tags = set()
        for finding in self.findings:
            tags = finding.tags
            unique_tags.update(tags)
        return list(unique_tags)
