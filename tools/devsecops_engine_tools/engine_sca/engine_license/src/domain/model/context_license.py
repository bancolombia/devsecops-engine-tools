from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ContextLicense:
    name: str
    version: str
    licenses: List[str]
    policy_applied: str
    policy_reason: str
    policy_pattern_matched: str
    severity: str
    priority: Optional[str] = field(default=None)
