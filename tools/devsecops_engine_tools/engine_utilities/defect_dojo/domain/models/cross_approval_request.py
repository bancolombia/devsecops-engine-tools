import dataclasses
from typing import List, Optional

from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import (
    FromDictMixin,
)


@dataclasses.dataclass
class CrossApprovalComponent(FromDictMixin):
    type: str = ""
    values: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CrossApprovalExclusion(FromDictMixin):
    id: str = ""
    where: str = ""
    create_date: str = ""
    expired_date: str = ""
    expired_at: Optional[str] = None
    severity: str = ""
    priority: str = ""
    hu: str = ""
    reason: str = ""
    cve_id: str = ""
    component: CrossApprovalComponent = dataclasses.field(
        default_factory=CrossApprovalComponent
    )


@dataclasses.dataclass
class CrossApprovalRequest(FromDictMixin):
    status: str = ""
    exclusions: List[CrossApprovalExclusion] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CrossApprovalRequestList(FromDictMixin):
    count: int = 0
    next: Optional[str] = None
    previous: Optional[str] = None
    results: List[CrossApprovalRequest] = dataclasses.field(default_factory=list)