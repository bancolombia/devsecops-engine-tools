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
    engagement_end_date: str = ""
    source_code_management_uri: str = ""
    engagement: int = 0
    engagement_id: int = 0
    auto_create_context: str = ""
    deduplication_on_engagement: str = ""
    lead: str = ""
    tags: str = ""
    close_old_findings: str = ""
    close_old_findings_product_scope: str = ""
    push_to_jira: str = ""
    environment: str = ""
    version: str = ""
    build_id: str = ""
    branch_tag: str = ""
    commit_hash: str = ""
    api_scan_configuration: int = 0
    test_id: int = 0
    service: str = ""
    group_by: str = ""
    create_finding_groups_for_all_findings: str = ""
    # ****another parameter outside defect dojo*****
    product_description: str = ""
    tools_configuration: str = ""
    code_app: str = ""
    token_cmdb: str = ""
    host_cmdb: str = ""
    token_defect_dojo: str = ""
    host_defect_dojo: str = ""
    # *** config map ***
    organization_url: str = ""
    personal_access_token: str = ""
    repository_id: str = ""
    remote_config_path: str = ""
    project_remote_config: str = ""
    cmdb_mapping: dict = None
    product_type_name_mapping: dict = None
    compact_remote_config_url: str = None
    # ** Expression
    expression: str = ""
    # ** Test url
    url: str = ""

    @classmethod
    def from_dict(cls, obj):
        obj = cls(
            scan_date=obj.get("scan_date"),
            minimum_severity=obj.get("minimum_severity"),
            active=obj.get("active"),
            verified=obj.get("verified"),
            scan_type=obj.get("scan_type"),
            endpoint_to_add=obj.get("endpoint_to_add"),
            file=obj.get("file"),
            product_type_name=obj.get("product_type_name"),
            product_name=obj.get("product_name"),
            engagement_name=obj.get("engagement_name"),
            engagement_end_date=obj.get("engagement_end_date"),
            source_code_management_uri=obj.get("source_code_management_uri"),
            engagement=obj.get("engagement"),
            engagement_id=obj.get("engagement_id"),
            auto_create_context=obj.get("auto_create_context"),
            deduplication_on_engagement=obj.get("deduplication_on_engagement"),
            lead=obj.get("lead"),
            tags=obj.get("tags"),
            close_old_findings=obj.get("close_old_findings"),
            close_old_findings_product_scope=obj.get("close_old_findings_product_scope"),
            push_to_jira=obj.get("push_to_jira"),
            environment=obj.get("environment"),
            version=obj.get("version"),
            build_id=obj.get("build_id"),
            branch_tag=obj.get("branch_tag"),
            commit_hash=obj.get("commit_hash"),
            api_scan_configuration=obj.get("api_scan_configuration"),
            test_id=obj.get("test_id"),
            service=obj.get("service"),
            group_by=obj.get("group_by"),
            create_finding_groups_for_all_findings=obj.get("create_finding_groups_for_all_findings"),
            organization_url=obj.get("organization_url"),
            personal_access_token=obj.get("personal_access_token"),
            repository_id=obj.get("remote_config_repo"),
            remote_config_path=obj.get("remote_config_path"),
            project_remote_config=obj.get("project_remote_config"),
            cmdb_mapping=obj.get("cmdb_mapping"),
            product_type_name_mapping=obj.get("product_type_name_mapping"),
            expression=obj.get("expression"),
            compact_remote_config_url=obj.get("compact_remote_config_url"),
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
