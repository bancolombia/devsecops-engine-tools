class WaConfig:
    def __init__(self, data: dict):
        self.target_type: str = "WA"
        self.url: str = data["endpoint"]
        self.data: dict = data.wa_data