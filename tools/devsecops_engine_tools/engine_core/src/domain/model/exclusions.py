from dataclasses import dataclass


@dataclass
class Exclusions:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "")
        self.where = kwargs.get("where", "all")
        self.cve_id = kwargs.get("cve_id", "")
        self.create_date = kwargs.get("create_date", "")
        self.expired_date = kwargs.get("expired_date", "")
        self.severity = kwargs.get("severity", "")
        self.hu = kwargs.get("hu", "")
        self.reason = kwargs.get("reason", "DevSecOps policy")
        self.vm_id = kwargs.get("vm_id", "")
        self.vm_id_url = kwargs.get("vm_id_url", "")
        self.service = kwargs.get("service", "")
        self.tags = kwargs.get("tags", [])
        self.check_in_desc = kwargs.get("x86.image.name", [])
