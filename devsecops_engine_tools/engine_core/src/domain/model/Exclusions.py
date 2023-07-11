from dataclasses import dataclass

@dataclass
class Exclusions:
    check_id : str
    cve_id : str
    create_date : str
    expired_date : str
    severity : str
    hu : str
