class HandleFilters:
    def __init__(
        self,
        remote_config,
    ):
        self.remote_config = remote_config

    def filter(self, findings):
        tag_list = self.remote_config["TAG_FILTER"]
        severity_list = ["critical", "high", "medium", "low"]
        return list(
            filter(
                lambda finding: finding.active
                and any(tag in finding.tags for tag in tag_list)
                and (finding.severity.lower() in severity_list),
                findings,
            )
        )
