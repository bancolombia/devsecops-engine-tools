class TargetConfig:
    def __init__(self, data: dict):
        self.url: str = data.get("endpoint")
        self.target_type: str = self.match_target_type(data)
        self.data: dict = data

    def match_target_type(self, data):
        if "operations" in data:
            return "API"
        else:
            return "AW"
