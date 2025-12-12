class LevelPriority:
    def __init__(self, data_priority):
        self.very_critical_priority = data_priority.get("Very Critical")
        self.critical_priority = data_priority.get("Critical")
        self.high_priority = data_priority.get("High")
        self.medium_low_priority = data_priority.get("Medium Low")