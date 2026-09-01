import dataclasses
from typing import Optional


@dataclasses.dataclass
class FindingRequest:
    active: bool = True
    component_name: str = ""
    component_version: str = ""
    created: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    cvssv3: str = ""
    cvssv3_score: float = 0.0
    cwe: Optional[int] = None
    date: str = ""
    defect_review_requested_by: Optional[int] = None
    description: str = ""
    duplicate: bool = True
    duplicate_finding: int = 0
    dynamic_finding: bool = False
    effort_for_fixing: str = ""
    endpoints: Optional[int] = None
    false_p: bool = False
    file_path: str = ""
    finding_group: Optional[int] = None
    found_by: int = 0
    has_jira: bool = False
    has_tags: bool = False
    hash_code: str = ""
    id: Optional[int] = None
    impact: str = ""
    inherited_tags: Optional[str] = None
    is_mitigated: bool = False
    jira_change: str = ""
    jira_creation: str = ""
    last_reviewed: str = ""
    last_reviewed_by: Optional[int] = None
    limit: int = 0
    mitigated: str = ""
    mitigated_by: Optional[int] = None
    mitigation: str = ""
    nb_occurences: Optional[int] = None
    not_tag: str = ""
    not_tags: Optional[str] = None
    not_test__engagement__product__tags: Optional[str] = None
    not_test__engagement__tags: Optional[str] = None
    not_test__tags: Optional[str] = None
    numerical_severity: str = ""
    offset: int = 0
    out_of_scope: bool = False
    outside_of_sla: int = 0
    param: str = ""
    payload: str = ""
    planned_remediation_date: str = ""
    planned_remediation_version: str = ""
    prefetch: Optional[str] = None
    product_name: str = ""
    product_name_contains: str = ""
    publish_date: str = ""
    references: str = ""
    related_fields: str = ""
    reporter: Optional[int] = None
    review_request_by: Optional[int] = None
    reviewers: Optional[str] = None
    risk_accetance: int = 0
    risk_accepted: bool = False
    sast_sink_object: str = ""
    sast_source_object: str = ""
    scanner_confidence: Optional[int] = None
    service: str = ""
    severity: str = ""
    severity_justification: str = ""
    sla_start_date: str = ""
    sonarqube_issue: Optional[int] = None
    static_finding: bool = False
    steps_to_reproduce: str = ""
    tag: str = ""
    tags: str = ""
    test: Optional[int] = None
    test__engagement: Optional[int] = None
    test__engagement__product: Optional[int] = None
    test__engagement__product__prod_type: Optional[int] = None
    test__engagement__product__tags: Optional[str] = None
    test__engagement__tags: Optional[str] = None
    test__tags: Optional[str] = None
    test__test_type: Optional[int] = None
    title: str = ""
    under_defect_review: bool = False
    under_review: bool = False
    unique_id_from_tool: str = ""
    verified: bool = False
    vuln_id_from_tool: str = ""
    vulnerability_id: str = ""

    @classmethod
    def from_dict(cls, obj):
        obj = cls(unique_id_from_tool=obj.get("unique_id_from_tool"))
