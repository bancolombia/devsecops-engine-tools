import dataclasses
from typing import List, Optional
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class Product(FromDictMixin):
    id: int = 0
    findings_count: int = 0
    findings_list: List[None] = dataclasses.field(default_factory=list)
    tags: List[None] = dataclasses.field(default_factory=list)
    product_meta: List[None] = dataclasses.field(default_factory=list)
    name: int = ""
    description: str = ""
    created: str = ""
    prod_numeric_grade: int = 0
    business_criticality: Optional[str] = None
    platform: Optional[str] = None
    lifecycle: Optional[str] = None
    origin: Optional[str] = None
    user_records: Optional[int] = None
    revenue: Optional[str] = None
    external_audience: Optional[bool] = None
    internet_accessible: Optional[bool] = None
    enable_simple_risk_acceptance: Optional[bool] = None
    enable_full_risk_acceptance: Optional[bool] = None
    disable_sla_breach_notifications: Optional[bool] = None
    product_manager: Optional[int] = None
    technical_contact: Optional[int] = None
    team_manager: Optional[int] = None
    prod_type: int = 0
    sla_configuration: int = 0
    members: List[int] = dataclasses.field(default_factory=list)
    authorization_groups: List[None] = dataclasses.field(default_factory=list)
    regulations: List[None] = dataclasses.field(default_factory=list)
