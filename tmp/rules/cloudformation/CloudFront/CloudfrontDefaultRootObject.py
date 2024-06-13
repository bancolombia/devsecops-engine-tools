from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


def is_not_empty(a):
    return len(a) > 0


class CloudfrontDefaultRootObject(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront has DefaultRootObject configured"
        id = "CKV_AWS_286"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'DefaultRootObject' in conf['Properties']['DistributionConfig'].keys():
                    if '/' not in conf['Properties']['DistributionConfig']['DefaultRootObject'] and is_not_empty(conf['Properties']['DistributionConfig']['DefaultRootObject']):
                        return CheckResult.PASSED

        return CheckResult.FAILED


check = CloudfrontDefaultRootObject()
