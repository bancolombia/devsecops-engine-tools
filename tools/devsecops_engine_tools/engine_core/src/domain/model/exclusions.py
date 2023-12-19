from dataclasses import dataclass


@dataclass
class Exclusions:
    id: str = ""
    where: str = ""
    cve_id: str = ""
    create_date: str = ""
    expired_date: str = ""
    severity: str = ""
    hu: str = ""
