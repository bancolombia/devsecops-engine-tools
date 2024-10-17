from marshmallow import Schema, fields, post_load, validate
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import ImportScanRequest

list_scan_type = [
    "Acunetix Scan",
    "Acunetix360 Scan",
    "Anchore Engine Scan",
    "Anchore Enterprise Policy Check",
    "Anchore Grype",
    "AnchoreCTL Policies Report",
    "AnchoreCTL Vuln Report",
    "AppSpider Scan",
    "Aqua Scan",
    "Arachni Scan",
    "AuditJS Scan",
    "AWS Prowler Scan",
    "AWS Scout2 Scan",
    "AWS Security Finding Format (ASFF) Scan",
    "AWS Security Hub Scan",
    "Azure Security Center Recommendations Scan",
    "Bandit Scan",
    "Bearer CLI",
    "BlackDuck API",
    "Blackduck Component Risk",
    "Blackduck Hub Scan",
    "Brakeman Scan",
    "Bugcrowd API Import",
    "BugCrowd Scan",
    "Bundler-Audit Scan",
    "Burp Enterprise Scan",
    "Burp GraphQL API",
    "Burp REST API",
    "Burp Scan",
    "CargoAudit Scan",
    "Checkmarx OSA",
    "Checkmarx Scan",
    "Checkmarx Scan detailed",
    "Checkov Scan",
    "Clair Klar Scan",
    "Clair Scan",
    "Cloudsploit Scan",
    "Cobalt.io API Import",
    "Cobalt.io Scan",
    "Codechecker Report native",
    "Contrast Scan",
    "Coverity API",
    "Crashtest Security JSON File",
    "Crashtest Security XML File",
    "CredScan Scan",
    "CycloneDX Scan",
    "DawnScanner Scan",
    "Dependency Check Scan",
    "Dependency Track Finding Packaging Format (FPF) Export",
    "Detect-secrets Scan",
    "docker-bench-security Scan",
    "Dockle Scan",
    "DrHeader JSON Importer",
    "DSOP Scan",
    "Edgescan Scan",
    "ESLint Scan",
    "Fortify Scan",
    "Generic Findings Import",
    "Ggshield Scan",
    "Github Vulnerability Scan",
    "GitLab API Fuzzing Report Scan",
    "GitLab Container Scan",
    "GitLab DAST Report",
    "GitLab Dependency Scanning Report",
    "GitLab SAST Report",
    "GitLab Secret Detection Report",
    "Gitleaks Scan",
    "Gosec Scanner",
    "HackerOne Cases",
    "Hadolint Dockerfile check",
    "Harbor Vulnerability Scan",
    "Horusec Scan",
    "HuskyCI Report",
    "Hydra Scan",
    "IBM AppScan DAST",
    "Immuniweb Scan",
    "IntSights Report",
    "JFrog Xray API Summary Artifact Scan",
    "JFrog Xray On Demand Binary Scan",
    "JFrog Xray Scan",
    "JFrog Xray Unified Scan",
    "KICS Scan",
    "Kiuwan Scan",
    "kube-bench Scan",
    "Meterian Scan",
    "Microfocus Webinspect Scan",
    "MobSF Scan",
    "Mobsfscan Scan",
    "Mozilla Observatory Scan",
    "Nessus Scan",
    "Nessus WAS Scan",
    "Netsparker Scan",
    "NeuVector (compliance)",
    "NeuVector (REST)",
    "Nexpose Scan",
    "Nikto Scan",
    "Nmap Scan",
    "Node Security Platform Scan",
    "NPM Audit Scan",
    "Nuclei Scan",
    "Openscap Vulnerability Scan",
    "OpenVAS CSV",
    "ORT evaluated model Importer",
    "OssIndex Devaudit SCA Scan Importer",
    "Outpost24 Scan",
    "PHP Security Audit v2",
    "PHP Symfony Security Check",
    "pip-audit Scan",
    "PMD Scan",
    "PWN SAST",
    "Qualys Infrastructure Scan (WebGUI XML)",
    "Qualys Scan",
    "Qualys Webapp Scan",
    "Retire.js Scan",
    "Risk Recon API Importer",
    "Rubocop Scan",
    "Rusty Hog Scan",
    "SARIF",
    "Scantist Scan",
    "Scout Suite Scan",
    "Semgrep JSON Report",
    "SKF Scan",
    "Snyk Scan",
    "Solar Appscreener Scan",
    "SonarQube API Import",
    "SonarQube Scan",
    "SonarQube Scan detailed",
    "Sonatype Application Scan",
    "SpotBugs Scan",
    "SSL Labs Scan",
    "Sslscan",
    "Sslyze Scan",
    "SSLyze Scan (JSON)",
    "StackHawk HawkScan",
    "Talisman Scan",
    "Terrascan Scan",
    "Testssl Scan",
    "TFSec Scan",
    "Trivy Operator Scan",
    "Trivy Scan",
    "Trufflehog Scan",
    "Trufflehog3 Scan",
    "Trustwave Fusion API Scan",
    "Trustwave Scan (CSV)",
    "Twistlock Image Scan",
    "VCG Scan",
    "Veracode Scan",
    "Veracode SourceClear Scan",
    "Vulners",
    "Wapiti Scan",
    "Wazuh",
    "WFuzz JSON report",
    "Whispers Scan",
    "WhiteHat Sentinel",
    "Whitesource Scan",
    "Wpscan",
    "Xanitizer Scan",
    "Yarn Audit Scan",
    "ZAP Scan",
]
group_by_list = ["component_name", "component_name+component_version", "file_path", "finding_title"]


class ImportScanSerializer(Schema):
    scan_date = fields.Str(required=False)
    minimum_severity = fields.Str(required=False)
    active = fields.Str(required=False, load_default="true")
    verified = fields.Str(required=False, load_default="true")
    scan_type = fields.Str(required=True, validate=validate.OneOf(list_scan_type))
    endpoint_to_add = fields.Str(required=False)
    file = fields.Str(required=False)
    product_type_name = fields.Str(required=False)
    product_name = fields.Str(required=False)
    engagement_name = fields.Str(required=True)
    engagement_end_date = fields.Str(required=False)
    source_code_management_uri = fields.Str(required=False)
    engagement = fields.Int(required=False)
    auto_create_context = fields.Str(required=False, load_default="true")
    deduplication_on_engagement = fields.Str(required=False)
    lead = fields.Str(required=False)
    tags = fields.Str(required=True)
    close_old_findings = fields.Str(required=False, load_default=True)
    close_old_findings_product_scope = fields.Str(required=False)
    push_to_jira = fields.Str(required=False)
    environment = fields.Str(
        required=False,
        validate=validate.OneOf(["Development", "Production", "Default", "Staging", "Test", "Pre-prod", "Lab"]),
    )
    version = fields.Str(required=False)
    build_id = fields.Str(required=False)
    branch_tag = fields.Str(required=False)
    commit_hash = fields.Str(required=False)
    api_scan_configuration = fields.Int(required=False)
    service = fields.Str(required=False)
    group_by = fields.Str(required=False)
    test_title = fields.Str(required=False)
    description_product = fields.Str(required=False)
    create_finding_groups_for_all_findings = fields.Str(required=False)
    tools_configuration = fields.Int(required=False, load_default=1)
    code_app = fields.Str(required=False)
    # defect-dojo credential
    token_cmdb = fields.Str(required=True)
    host_cmdb = fields.Url(required=True)
    token_defect_dojo = fields.Str(required=True)
    host_defect_dojo = fields.Str(required=True)
    cmdb_mapping = fields.Dict(required=True)
    product_type_name_mapping = fields.Dict(required=False)
    # Config remote credential
    compact_remote_config_url = fields.Str(required=False)
    organization_url = fields.Str(required=False)
    personal_access_token = fields.Str(required=False)
    repository_id = fields.Str(required=False)
    remote_config_path = fields.Str(required=False)
    project_remote_config = fields.Str(required=False)
    # regulare expression
    expression = fields.Str(required=True)

    @post_load
    def make_cmdb(self, data, **kwargs):
        return ImportScanRequest(**data)
