class HandleFilters:

    def filter(self, findings):
        severity_list = ["critical", "high", "medium", "low"]
        return list(
            filter(
                lambda finding: finding.active
                and (finding.severity.lower() in severity_list),
                findings,
            )
        )
