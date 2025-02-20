import dataclasses
from typing import List
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
    request_response = None
    req_resp: List[None] = dataclasses.field(default_factory=list)
    accepted_risks: List[None] = dataclasses.field(default_factory=list)
    transfer_finding: TransferFinding = None
    push_to_jira: bool = False
    age: int = 0
    sla_days_remaining: int = 0
    finding_meta: List[None] = dataclasses.field(default_factory=list)
    related_fields = None
    jira_creation = None
    jira_change = None
    display_status: str = ""
    finding_groups: List[None] = dataclasses.field(default_factory=list)
    vulnerability_ids: List[None] = dataclasses.field(default_factory=list)
    reporter: int = 0
    title: int = 0
    date: str = ""
    sla_start_date = None
    cwe: int = 0
    epss_score: int = 0
    epss_percentile: int = 0
    cvssv3 = None
    cvssv3_score = None
    url: str = ""
    severity: str = ""
    description: str = ""
    mitigation = None
    impact = None
    steps_to_reproduce = None
    severity_justification = None
    references = None
    active: bool = None
    verified: bool = None
    false_p: bool = None
    duplicate: bool = None
    out_of_scope: bool = None
    risk_status: str = ""
    risk_accepted: bool = None
    under_review: bool = None
    last_status_update: str = ""
    under_defect_review: bool = None
    is_mitigated: bool = None
    thread_id: int = -1
    mitigated = None
    numerical_severity: str = ""
    last_reviewed: str = ""
    param = None
    payload = None
    hash_code: str = ""
    line = None
    file_path: str = ""
    component_name: str = ""
    component_version: str = ""
    static_finding: bool = None
    dynamic_finding: bool = None
    created: str = ""
    service: str = ""
    scanner_confidence = None
    unique_id_from_tool: str = ""
    vuln_id_from_tool: str = ""
    sast_source_object = None
    sast_sink_object = None
    sast_source_line = None
    sast_source_file_path = None
    nb_occurences = None
    publish_date: str = ""
    planned_remediation_date = None
    planned_remediation_version = None
    effort_for_fixing = None
    test: int = -1
    duplicate_finding = None
    review_requested_by = None
    defect_review_requested_by = None
    mitigated_by = None
    last_reviewed_by: int = -1
    sonarqube_issue = None
    endpoints: List[None] = dataclasses.field(default_factory=list)
    reviewers: List[None] = dataclasses.field(default_factory=list)
    notes: List[None] = dataclasses.field(default_factory=list)
    files: List[None] = dataclasses.field(default_factory=list)
    found_by: List[None] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class FindingList(FromDictMixin):
    count: int = 0
    next = None
    previous = None
    results: List[Finding] = dataclasses.field(default_factory=list)
    prefetch = None
