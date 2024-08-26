from marshmallow import Schema, fields, validate


class FindingSerializer(Schema):
    active = fields.Bool(requeride=False)
    component_name = fields.Str(requeride=False)
    component_version = fields.Str(requeride=False)
    created = fields.Str(requeride=False)
    cvssv3 = fields.Str(requeride=False)
    cvssv3_score = fields.Int(requeride=False)
    cwe = fields.List(fields.Int, requeride=False)
    date = fields.Str(requeride=False)
    defect_review_requested_by = fields.List(fields.Int, requerided=False)
    description = fields.Str(requeride=False)
    duplicate = fields.Bool(requerided=False)
    duplicate_finding = fields.Int(requerided=False)
    dynamic_finding = fields.Bool(requerided=False)
    effort_for_fixing = fields.Str(requerided=False)
    endpoints = fields.List(fields.Int, requerided=False)
    false_p = fields.Bool(requerided=False)
    file_path = fields.Str(requeride=False)
    finding_group = fields.List(fields.Number, requerided=False)
    found_by = fields.List(fields.Int, requerided=False)
    has_jira = fields.Bool(requerided=False)
    has_tags = fields.Bool(requerided=False)
    hash_code = fields.Str(requeride=False)
    id = fields.List(fields.List(fields.Field()), requerided=False)
    impact = fields.Str(requeride=False)
    inherited_tags = fields.List(fields.List(fields.Field()), requeride=False)
    is_mitigated = fields.Bool(requerided=False)
    jira_change = fields.Str(requeride=False)
    jira_creation = fields.Str(requeride=False)
    last_reviewed = fields.Str(requeride=False)
    last_reviewed_by = fields.List(fields.Int, requeried=False)
    limit = fields.Int(requerided=False)
    mitigated = fields.Str(requeride=False)
    mitigated_by = fields.List(fields.Int, requerided=False)
    mitigation = fields.Str(requeride=False)
    nb_occurences = fields.List(fields.Int, requeride=False)
    not_tag = fields.Str(requeride=False)
    not_tags = fields.List(fields.Str, requerided=False)
    not_test__engagement__product__tags = fields.List(fields.Str, requerided=False)
    not_test__engagement__tags = fields.List(fields.Str, requerided=False)
    not_test__tags = fields.List(fields.Str, requerided=False)
    numerical_severity = fields.Str(requeride=False)
    offset = fields.Int(requerided=False)
    out_of_scope = fields.Bool(requerided=False)
    outside_of_sla = fields.Int(requerided=False)
    param = fields.Str(requeride=False)
    payload = fields.Str(requeride=False)
    planned_remediation_date = fields.Str(requeride=False)
    planned_remediation_version = fields.Str(requeride=False)
    prefetch = fields.List(fields.Str, requerided=False)
    product_name = fields.Str(requeride=False)
    product_name_contains = fields.Str(requeride=False)
    publish_date = fields.Str(requeride=False)
    references = fields.Str(requeride=False)
    related_fields = fields.Str(requeride=False)
    reporter = fields.List(fields.Int, requerided=False)
    review_request_by = fields.List(fields.Int, requerided=False)
    reviewers = fields.List(fields.Int, requerided=False)
    risk_accetance = fields.Int(requerided=False)
    risk_status = fields.Str(
        required=False, validate=validate.OneOf(["Risk Pending", "Risk Rejected", "Risk Expired", "Risk Accepted", "Risk Active", "Transfer Pending", "Transfer Rejected", "Transfer Expired", "Transfer Accepted"])
    )
    risk_accepted = fields.Bool(requerided=False)
    sast_sink_object = fields.Str(requeride=False)
    sast_source_object = fields.Str(requeride=False)
    scanner_confidence = fields.List(fields.Int, requerided=False)
    service = fields.Str(requeride=False)
    severity = fields.Str(requeride=False)
    severity_justification = fields.Str(requeride=False)
    sla_start_date = fields.Str(requeride=False)
    sonarqube_issue = fields.List(fields.Int, requerided=False)
    static_finding = fields.Bool(requerided=False)
    steps_to_reproduce = fields.Str(requeride=False)
    tag = fields.Str(requeride=False)
    tags = fields.Str(requeride=False)
    test = fields.Int(requerided=False)
    test__engagement = fields.List(fields.Int, requerided=False)
    test__engagement__product = fields.List(fields.Int, requerided=False)
    test__engagement__product__prod_type = fields.List(fields.Int, requerided=False)
    test__engagement__product__tags = fields.List(fields.Int, requerided=False)
    test__engagement__tags = fields.List(fields.Str, requerided=False)
    test__tags = fields.List(fields.Str, requerided=False)
    test__test_type = fields.List(fields.Int, requerided=False)
    title = fields.Str(requeride=False)
    under_defect_review = fields.Bool(requerided=False)
    under_review = fields.Bool(requerided=False)
    unique_id_from_tool = fields.Str(requeride=False)
    verified = fields.Bool(requerided=False)
    vuln_id_from_tool = fields.Str(requeride=False)
    vulnerability_id = fields.Str(requeride=False)


class FindingCloseSerializer(Schema):
    is_mitigated = fields.Bool(default=True, requerided=False)
    mitigated = fields.Bool(requerided=False)
    detail = fields.Str(required=False)
    message = fields.Str(required=False)
