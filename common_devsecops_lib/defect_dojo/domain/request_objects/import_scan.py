import dataclasses


@dataclasses.dataclass
class ImportScanRequest:
    scan_date: str = ""
    minimum_severity: str = ""
    active: str = ""
    verified: str = ""
    scan_type: str = ""
    endpoint_to_add: str = ""
    file: str = ""
    product_type_name: str = ""
    product_name: str = ""
    engagement_name: str = ""
    engagement: int = 0
    auto_create_context: str = ""
    deduplication_on_engagement: str = ""
    lead: str = ""
    tags: str = ""
    close_old_findings: str = ""
    close_old_findings_product_scope: str = ""
    push_to_jira: str = ""
    environment: str = ""
    build_id: str = ""
    branch_tag: str = ""
    commit_hash: str = ""
    api_scan_configuration: int = 0
    service: str = ""
    group_by: str = ""
    test_title: str = ""
    product_description: str = ""
    create_finding_groups_for_all_findings: str = ""
    tools_configuration: str = ""
    code_app: str = ""
    token: str = ""
    host: str = ""
    token_vultracker: str = ""
    host_vultracker: str = ""

    @classmethod
    def from_dict(cls, obj):
        obj = cls(
            minimum_severity=obj.get("minimum_severity"),
            active=obj.get("active"),
            verified=obj.get("verified"),
            scan_type=obj.get("scan_type"),
            endpoint_to_add=obj.get("endpoint_to_add"),
            file=obj.get("file"),
            product_type_name=obj.get("product_type_name"),
            product_name=obj.get("product_name"),
            engagement_name=obj.get("engagement_name"),
            auto_create_context=obj.get("auto_create_context"),
            deduplication_on_engagement=obj.get("deduplication_on_engagement"),
            lead=obj.get("lead"),
            close_old_findings=obj.get("close_old_findings"),
            close_old_findings_product_scope=obj.get("close_old_findings_product_scope"),
            push_to_jira=obj.get("push_to_jira"),
            api_scan_configuration=obj.get("api_scan_configuration"),
            create_finding_groups_for_all_findings=obj.get("create_finding_groups_for_all_findings"),
        )
        return obj

    def to_dict(self):
        r = {
            "minimum_severity": self.minimum_severity,
            "active": self.active,
            "verified": self.verified,
            "scan_type": self.scan_type,
            "endpoint_to_add": self.endpoint_to_add,
            "file": self.file,
            "product_type_name": self.product_type_name,
            "product_name": self.product_name,
            "engagement_name": self.engagement_name,
            "auto_create_context": self.auto_create_context,
            "deduplication_on_engagement": self.deduplication_on_engagement,
            "lead": self.lead,
            "close_old_findings": self.close_old_findings,
            "close_old_findings_product_scope": self.close_old_findings_product_scope,
            "push_to_jira": self.push_to_jira,
            "api_scan_configuration": self.api_scan_configuration,
            "build_id": self.build_id,
        }
        return r
