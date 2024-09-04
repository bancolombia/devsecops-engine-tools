from dataclasses import dataclass


@dataclass
class Report:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", [])
        self.vuln_id_from_tool = kwargs.get("vuln_id_from_tool", "")
        self.where = kwargs.get("where", "")
        self.tags = kwargs.get("tags", [])
        self.severity = kwargs.get("severity", "")
        self.age = kwargs.get("age", "")
        self.active = kwargs.get("active", "")
        self.status = kwargs.get("status", "")
        self.risk_status = kwargs.get("risk_status", "")
        self.risk_score = kwargs.get("risk_score", "")
        self.created = kwargs.get("created", "")
        self.publish_date = kwargs.get("publish_date", "")
        self.last_reviewed = kwargs.get("last_reviewed", "")
        self.last_status_update = kwargs.get("last_status_update", "")
        self.accepted_risks = kwargs.get("accepted_risks", "")
        self.transfer_finding = kwargs.get("transfer_finding", "")
        self.epss_score = kwargs.get("epss_score", "")
        self.epss_percentile = kwargs.get("epss_percentile", "")
        self.mitigated = kwargs.get("mitigated", "")
        self.vul_description = kwargs.get("vul_description", "")
        self.risk_accepted = kwargs.get("risk_accepted", "")
        self.false_p = kwargs.get("false_p", "")
        self.service = kwargs.get("service", "")
        self.reason = kwargs.get("reason", "")
        self.component_name = kwargs.get("component_name", "")
        self.component_version = kwargs.get("component_version", "")
        self.file_path = kwargs.get("file_path", "")
        self.endpoints = kwargs.get("endpoints", "")