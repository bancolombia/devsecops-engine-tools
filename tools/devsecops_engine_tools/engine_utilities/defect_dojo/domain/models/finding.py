import dataclasses
from typing import Any, List, Optional
from devsecops_engine_tools.engine_utilities.utils.dataclass_classmethod import FromDictMixin

@dataclasses.dataclass
class TransferFinding(FromDictMixin):
    id: int = 0
    date : str = ""
    expiration_date: str = ""

@dataclasses.dataclass
class Finding(FromDictMixin):
    id: int = 0
    tags: List[None] = dataclasses.field(default_factory=list)
    request_response: Optional[Any] = None
    req_resp: List[None] = dataclasses.field(default_factory=list)
    accepted_risks: List[None] = dataclasses.field(default_factory=list)
    transfer_finding: Optional[TransferFinding] = None
    push_to_jira: bool = False
    age: int = 0
    sla_days_remaining: int = 0
    finding_meta: List[None] = dataclasses.field(default_factory=list)
    related_fields: Optional[Any] = None
    jira_creation: Optional[str] = None
    jira_change: Optional[str] = None
    display_status: str = ""
    finding_groups: List[None] = dataclasses.field(default_factory=list)
    vulnerability_ids: List[None] = dataclasses.field(default_factory=list)
    reporter: int = 0
    title: int = 0
    date: str = ""
    sla_start_date: Optional[str] = None
    cwe: int = 0
    epss_score: int = 0
    epss_percentile: int = 0
    cvssv3: Optional[str] = None
    cvssv3_score: Optional[float] = None
    url: str = ""
    severity: str = ""
    description: str = ""
    mitigation: Optional[str] = None
    impact: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    severity_justification: Optional[str] = None
    references: Optional[str] = None
    active: Optional[bool] = None
    verified: Optional[bool] = None
    false_p: Optional[bool] = None
    duplicate: Optional[bool] = None
    out_of_scope: Optional[bool] = None
    risk_status: str = ""
    risk_accepted: Optional[bool] = None
    under_review: Optional[bool] = None
    last_status_update: str = ""
    under_defect_review: Optional[bool] = None
    is_mitigated: Optional[bool] = None
    thread_id: int = -1
    mitigated: Optional[str] = None
    numerical_severity: str = ""
    last_reviewed: str = ""
    param: Optional[str] = None
    payload: Optional[str] = None
    hash_code: str = ""
    line: Optional[int] = None
    file_path: str = ""
    component_name: str = ""
    component_version: str = ""
    static_finding: Optional[bool] = None
    dynamic_finding: Optional[bool] = None
    created: str = ""
    service: str = ""
    scanner_confidence: Optional[int] = None
    unique_id_from_tool: str = ""
    vuln_id_from_tool: str = ""
    sast_source_object: Optional[str] = None
    sast_sink_object: Optional[str] = None
    sast_source_line: Optional[int] = None
    sast_source_file_path: Optional[str] = None
    nb_occurences: Optional[int] = None
    publish_date: str = ""
    planned_remediation_date: Optional[str] = None
    planned_remediation_version: Optional[str] = None
    effort_for_fixing: Optional[str] = None
    test: int = -1
    duplicate_finding: Optional[int] = None
    review_requested_by: Optional[int] = None
    defect_review_requested_by: Optional[int] = None
    mitigated_by: Optional[int] = None
    last_reviewed_by: int = -1
    sonarqube_issue: Optional[int] = None
    endpoints: List[None] = dataclasses.field(default_factory=list)
    reviewers: List[None] = dataclasses.field(default_factory=list)
    notes: List[None] = dataclasses.field(default_factory=list)
    files: List[None] = dataclasses.field(default_factory=list)
    found_by: List[None] = dataclasses.field(default_factory=list)
    priority_classification: str = ""
    priority: str = ""


@dataclasses.dataclass
class FindingList(FromDictMixin):
    count: int = 0
    next: Optional[str] = None
    previous: Optional[str] = None
    results: List[Finding] = dataclasses.field(default_factory=list)
    prefetch: Optional[Any] = None
