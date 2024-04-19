class HandleRemoteConfig:
    def __init__(
            self,
            remote_config,
            findings_list,
    ):
        self.remote_config = remote_config
        self.findings_list = findings_list

    def filter_by_tag(self):
        tag_list = self.remote_config["TAG_FILTER"]
        for finding in self.findings_list:
            for tag in tag_list:
                if not(tag in finding.tags):
                    self.findings_list.remove(finding)
        return self.findings_list


