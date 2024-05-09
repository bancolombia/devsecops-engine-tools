class HandleFilters:
    def __init__(
        self,
        remote_config,
    ):
        self.remote_config = remote_config

    def filter_by_tag(self, findings):
        tag_list = self.remote_config["TAG_FILTER"]
        findings_filtered = []
        for finding in findings:
            for tag in tag_list:
                if tag in finding.tags:
                    findings_filtered.append(finding)
        return findings_filtered

    def filter_by_status(self, findings):
        findings_filtered = []
        for finding in findings:
            if finding.active:
                findings_filtered.append(finding)
        return findings_filtered
