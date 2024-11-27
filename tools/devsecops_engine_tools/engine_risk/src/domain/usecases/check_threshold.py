import re


class CheckThreshold:
    def __init__(self, pipeline_name, threshold, risk_exclusions):
        self.pipeline_name = pipeline_name
        self.threshold = threshold
        self.risk_exclusions = risk_exclusions

    def process(self):
        if (self.pipeline_name in self.risk_exclusions.keys()) and (
            self.risk_exclusions[self.pipeline_name].get("THRESHOLD", None)
        ):
            return self.risk_exclusions[self.pipeline_name]["THRESHOLD"]
        elif "BY_PATTERN_SEARCH" in self.risk_exclusions.keys():
            for pattern, values in self.risk_exclusions["BY_PATTERN_SEARCH"].items():
                if re.match(pattern, self.pipeline_name):
                    return values["THRESHOLD"]
        return self.threshold
