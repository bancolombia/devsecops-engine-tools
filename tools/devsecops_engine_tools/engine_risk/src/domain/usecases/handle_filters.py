class HandleFilters:
    def __init__(
        self,
        remote_config: any,
    ):
        self.remote_config = remote_config

    def filter(self, findings):
        severity_list = self.remote_config['SEVERITY_LIST']
        return list(
            filter(
                lambda finding: finding.active
                and (finding.severity.lower() in severity_list),
                findings,
            )
        )
