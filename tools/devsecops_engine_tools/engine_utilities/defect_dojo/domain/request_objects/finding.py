import dataclasses


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
    cwe = None
    date: str = ""
    defect_review_requested_by = None
    description: str = ""
    duplicate: bool = True
    duplicate_finding = 0
    dynamic_finding: bool = False
    effort_for_fixing: str = ""
    endpoints = None
    false_p: bool = False
    file_path: str = ""
    finding_group = None
    found_by: int = 0
    has_jira: bool = False
    has_tags: bool = False
    hash_code: str = ""
    id = None
    impact: str = ""
    inherited_tags = None
    is_mitigated: bool = False
    jira_change: str = ""
    jira_creation: str = ""
    last_reviewed: str = ""
    last_reviewed_by = None
    limit: int = 0
    mitigated: str = ""
    mitigated_by = None
    mitigation: str = ""
    nb_occurences = None
    not_tag: str = ""
    not_tags = None
    not_test__engagement__product__tags = None
    not_test__engagement__tags = None
    not_test__tags = None
    numerical_severity: str = ""
    offset: int = 0
    out_of_scope: bool = False
    outside_of_sla: int = 0
    param: str = ""
    payload: str = ""
    planned_remediation_date: str = ""
    planned_remediation_version: str = ""
    prefetch = None
    product_name: str = ""
    product_name_contains: str = ""
    publish_date: str = ""
    references: str = ""
    related_fields: str = ""
    reporter = None
    review_request_by = None
    reviewers = None
    risk_accetance: int = 0
    risk_accepted: bool = False
    sast_sink_object: str = ""
    sast_source_object: str = ""
    scanner_confidence = None
    service: str = ""
    severity: str = ""
    severity_justification: str = ""
    sla_start_date: str = ""
    sonarqube_issue = None
    static_finding: bool = False
    steps_to_reproduce: str = ""
    tag: str = ""
    tags: str = ""
    test = None
    test__engagement = None
    test__engagement__product = None
    test__engagement__product__prod_type = None
    test__engagement__product__tags = None
    test__engagement__tags = None
    test__tags = None
    test__test_type = None
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
