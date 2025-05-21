from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ContextContainer:
    cve_id: str
    cwe_id: Optional[List[str]]
    vendor_id: Optional[List[str]]
    severity: str
    vulnerability_status: str
    target_image: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    description: str
    os_type: str
    layer_digest: Optional[str]
    published_date: Optional[str]
    last_modified_date: Optional[str]
    references: Optional[List[str]]
    source_tool: str
