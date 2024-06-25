from dataclasses import dataclass


@dataclass
class Report:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "")
        self.where = kwargs.get("where", "")
        self.tags = kwargs.get("tags", [])
        self.severity = kwargs.get("severity", "")
        self.active = kwargs.get("active", "")
        self.status = kwargs.get("status", "")
        self.risk_status = kwargs.get("risk_status", "")
        self.created = kwargs.get("created", "")
        self.last_reviewed = kwargs.get("last_reviewed", "")
        self.last_status_update = kwargs.get("last_status_update", "")
        self.vul_id = kwargs.get("vul_id", "")
        self.vul_description = kwargs.get("vul_description", "")
