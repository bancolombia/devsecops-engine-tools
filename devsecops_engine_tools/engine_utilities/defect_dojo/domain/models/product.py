import dataclasses
from typing import List
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
    business_criticality = None
    platform = None
    lifecycle = None
    origin = None
    user_records = None
    revenue = None
    external_audience: bool = None
    internet_accessible: bool = None
    enable_simple_risk_acceptance: bool = None
    enable_full_risk_acceptance: bool = None
    disable_sla_breach_notifications: bool = None
    product_manager = None
    technical_contact = None
    team_manager = None
    prod_type: int = 0
    sla_configuration: int = 0
    members: List[int] = dataclasses.field(default_factory=list)
    authorization_groups: List[None] = dataclasses.field(default_factory=list)
    regulations: List[None] = dataclasses.field(default_factory=list)
