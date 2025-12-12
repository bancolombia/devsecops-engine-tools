from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class Category(Enum):
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"

@dataclass
class Priority:
    score: float
    scale: str

@dataclass(kw_only=True)
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
    priority: Optional[Priority] = field(default=None)

@dataclass(kw_only=True)
class EngineCodeFinding(Finding):
    analysis_url: str
    analysis_code: str
    label: str
    application_business_value: str
    defect_type: str