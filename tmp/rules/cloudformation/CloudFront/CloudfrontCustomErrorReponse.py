from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class CloudfrontCustomErrorReponse(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloudfront has CustomErrorResponses"
        id = "CKV_AWS_285"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
 
        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'CustomErrorResponses' in conf['Properties']['DistributionConfig'].keys():
                    if isinstance(conf['Properties']['DistributionConfig']['CustomErrorResponses'], list):
                        for item in conf['Properties']['DistributionConfig']['CustomErrorResponses']:
                            if 'ErrorCode' not in item.keys() or 'ResponseCode' not in item.keys() or 'ResponsePagePath' not in item.keys():
                                return CheckResult.FAILED
                    
        return CheckResult.PASSED    

check = CloudfrontCustomErrorReponse()