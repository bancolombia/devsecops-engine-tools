class HandleFilters:
    def __init__(
        self,
        remote_config,
    ):
        self.remote_config = remote_config

    def filter(self, findings):
        tag_list = self.remote_config["TAG_FILTER"]
        return list(
            filter(
                lambda finding: finding.active
                and any(tag in finding.tags for tag in tag_list),
                findings,
            )
        )
