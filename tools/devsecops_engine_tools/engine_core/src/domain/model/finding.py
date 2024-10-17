from enum import Enum
from dataclasses import dataclass

class Category(Enum):
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"

@dataclass
class Finding:
    id: str
    cvss: str
    where: str
    description: str
    severity: str
    identification_date: str
    published_date_cve: str
    module: str
    category: Category
    requirements: str
    tool: str