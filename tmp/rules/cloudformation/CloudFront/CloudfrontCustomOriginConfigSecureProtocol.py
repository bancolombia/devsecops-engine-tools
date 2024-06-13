from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class CloudfrontCustomOriginConfigSecureProtocol(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront CustomOriginConfig has secure protocols"
        id = "CKV_AWS_282"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
 
        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'Origins' in conf['Properties']['DistributionConfig'].keys():
                    if isinstance(conf['Properties']['DistributionConfig']['Origins'], list):
                        for item in conf['Properties']['DistributionConfig']['Origins']:
                            if 'CustomOriginConfig' in item.keys():
                                if 'HTTPSPort' not in item['CustomOriginConfig'] or 'HTTPPort' in item['CustomOriginConfig']:
                                        return CheckResult.FAILED
                    
        return CheckResult.PASSED    

check = CloudfrontCustomOriginConfigSecureProtocol()
