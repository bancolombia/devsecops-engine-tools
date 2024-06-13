from typing import Any

from checkov.common.models.enums import CheckResult,CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.consts import ANY_VALUE

def is_not_empty(a):
    return len(a) > 0

class CloudfrontCertificate(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront distribution has certificate"
        id = "CKV_AWS_284"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Condition' in conf['Properties'] and 'ConCertificado' in str(conf['Properties']['Condition']):
                return CheckResult.UNKNOWN
            elif 'DistributionConfig' in conf['Properties'].keys():
                if "ViewerCertificate" in conf['Properties']['DistributionConfig']:
                    if "AcmCertificateArn" in conf['Properties']['DistributionConfig']['ViewerCertificate']:
                        if is_not_empty(conf['Properties']['DistributionConfig']['ViewerCertificate']['AcmCertificateArn']):                            
                            return CheckResult.PASSED
        return CheckResult.FAILED

check = CloudfrontCertificate()