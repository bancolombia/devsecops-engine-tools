from importlib.metadata import distribution
from typing import List
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class CloudfrontServerNameIndication(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront distribution has secure ServerNameIndication"
        id = "CKV_AWS_283"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        properties = conf.get('Properties')
        if properties is not None:
            distribution_config = properties.get('DistributionConfig')
            if distribution_config is not None:
                viewer_certificate = distribution_config.get('ViewerCertificate')
                if viewer_certificate is not None:
                    ssl_support_method = viewer_certificate.get('SslSupportMethod')
                    minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion')
                    if (ssl_support_method is not None and ssl_support_method != "sni-only") or (minimum_protocol_version is not None and minimum_protocol_version != "TLSv1.2_2021"):
                        return CheckResult.FAILED
        return CheckResult.PASSED

    def get_evaluated_keys(self) -> List[str]:
        return ["Properties/DistributionConfig/ViewerCertificate/SslSupportMethod", "Properties/DistributionConfig/ViewerCertificate/MinimumProtocolVersion"]


check = CloudfrontServerNameIndication()
