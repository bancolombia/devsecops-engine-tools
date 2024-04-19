class HandleFilters:
    def __init__(
            self,
            remote_config,
            findings_list,
    ):
        self.remote_config = remote_config
        self.findings_list = findings_list

    def filter_by_tag(self):
        tag_list = self.remote_config["TAG_FILTER"]
        new_findigs_list = []
        for finding in self.findings_list:
            for tag in tag_list:
                if tag in finding.tags:
                    new_findigs_list.append(finding)
        return self.findings_list


