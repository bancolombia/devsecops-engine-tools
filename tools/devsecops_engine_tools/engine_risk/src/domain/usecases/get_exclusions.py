from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)
from datetime import datetime, timedelta


class GetExclusions:
    def __init__(
        self,
        devops_platform_gateway,
        remote_config_source_gateway,
        dict_args,
        findings,
        risk_config,
        risk_exclusions,
        services,
        active_findings,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.remote_config_source_gateway = remote_config_source_gateway
        self.dict_args = dict_args
        self.findings = findings
        self.risk_config = risk_config
        self.risk_exclusions = risk_exclusions
        self.services = services
        self.active_findings = active_findings

    def process(self):
        core_config = self.remote_config_source_gateway.get_remote_config(
            self.dict_args["remote_config_repo"],
            "engine_core/ConfigTool.json",
            self.dict_args["remote_config_branch"],
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

        new_vuln_exclusions, len_new_vuln_exclusions = self._get_exclusions_new_vuln()
        exclusions.extend(new_vuln_exclusions)

        return exclusions, len_new_vuln_exclusions

    def _get_risk_exclusions(self):
        return self._get_exclusions(self.risk_exclusions, "RISK")

    def _get_exclusions_by_practice(self, core_config, practice, path):
        exclusions_config = self.remote_config_source_gateway.get_remote_config(
            self.dict_args["remote_config_repo"],
            path,
            self.dict_args["remote_config_branch"],
        )
        tool = core_config[practice.upper()]["TOOL"]
        return self._get_exclusions(exclusions_config, tool)

    def _get_exclusions(self, config, key):
        exclusions = []
        scope_list = ["All"] + self.services
        for scope in scope_list:
            if config.get(scope, None) and config[scope].get(key, None):
                exclusions.extend(
                    [
                        Exclusions(
                            **exclusion,
                        )
                        for exclusion in config[scope][key]
                        if exclusion.get("id", None)
                    ]
                )
        return exclusions

    def _get_unique_tags(self):
        unique_tags = set()
        for finding in self.findings:
            tags = finding.tags
            unique_tags.update(tags)
        return list(unique_tags)

    def _get_exclusions_new_vuln(self):
        cutoff_date = datetime.now() - timedelta(days=5)
        exclusions = []
        for finding in self.active_findings:
            if finding.publish_date:
                try:
                    finding_publish_date = datetime.strptime(
                        finding.publish_date, "%Y-%m-%d"
                    )
                except ValueError:
                    continue
                if finding_publish_date >= cutoff_date and hasattr(finding, "id"):
                    exclusion_data = finding.__dict__.copy()
                    exclusion_data["create_date"] = finding_publish_date.strftime(
                        "%d%m%Y"
                    )
                    exclusion_data["expired_date"] = (
                        finding_publish_date + timedelta(days=5)
                    ).strftime("%d%m%Y")
                    exclusion_data["reason"] = "New vulnerability in the industry"
                    exclusions.append(Exclusions(**exclusion_data))
                    finding.vul_description = finding.vul_description.replace(
                        "Image Base", ""
                    )
        return exclusions, len(exclusions)
