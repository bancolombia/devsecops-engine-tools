from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ContextDependencies:
    cve_id: List[str]
    severity: str
    component: str
    package_name: str
    installed_version: str
    fixed_version: Optional[List[str]]
    impact_paths: Optional[List[List[dict]]]
    description: str
    references: Optional[List[str]]
    source_tool: str