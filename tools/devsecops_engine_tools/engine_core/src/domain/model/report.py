from dataclasses import dataclass


@dataclass
class Report:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "")
        self.date = kwargs.get("date", "")
        self.where = kwargs.get("where", "")
        self.tags = kwargs.get("tags", [])
        self.severity = kwargs.get("severity", "")
        self.active = kwargs.get("active", "")
        self.status = kwargs.get("status", "")
