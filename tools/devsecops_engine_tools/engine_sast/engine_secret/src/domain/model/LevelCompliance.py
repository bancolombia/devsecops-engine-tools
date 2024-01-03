class LevelCompliance:
    def __init__(self, data):
        self.critical: int = data.get("Critical")
        self.high: int = data.get("High")
        self.medium: int = data.get("Medium")
        self.low: int = data.get("Low")
        self.unknown: int = data.get("Unknown")
