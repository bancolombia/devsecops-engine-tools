import dataclasses
from typing import Any, List, Optional
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin


@dataclasses.dataclass
class Engagement(FromDictMixin):
    id: int = 0
    tags: List[None] = dataclasses.field(default_factory=list)
    name: str = ""
    description: str = ""
    version: str = ""
    first_contacted: str = ""
    target_start: str = ""
    target_end: str = ""
    reason: str = ""
    updated: str = ""
    created: str = ""
    active: str = ""
    tracker: str = ""
    test_strategy: str = ""
    threat_model: str = ""
    api_test: str = ""
    pen_test: str = ""
    check_list: str = ""
    status: str = ""
    progress: str = ""
    tmodel_path: str = ""
    done_testing: str = ""
    engagement_type: str = ""
    build_id: str = ""
    commit_hash: str = ""
    branch_tag: str = ""
    source_code_management_uri: str = ""
    deduplication_on_engagement: str = ""
    lead: int = 0
    requester: str = ""
    preset: str = ""
    report_type: str = ""
    product: int = 0
    build_server: str = ""
    source_code_management_server: str = ""
    orchestration_engine: str = ""
    vm_url: str = ""
    notes: List[None] = dataclasses.field(default_factory=list)
    files: List[None] = dataclasses.field(default_factory=list)
    risk_acceptance: List[None] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class EngagementList(FromDictMixin):
    count: int = 0
    next: Optional[str] = None
    previous: Optional[str] = None
    results: List[Engagement] = dataclasses.field(default_factory=list)
    prefetch: Optional[Any] = None
