from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class NLBInternetRestriction(BaseResourceCheck):

    def __init__(self):
        name = "Ensure NLB has internet restriction"
        id = "CKV_AWS_370"
        supported_resources = ['AWS::ElasticLoadBalancingV2::LoadBalancer']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        white_list = {
            "subnet-0c8137727e851839f",
            "subnet-01650121b7375e2a7",
            "subnet-03893ef5201fdcd74",
            "subnet-047a6080ac4d27375",
            "subnet-0e8f0a8a89a694362",
            "subnet-0335e2952cf3b44c4",
            "subnet-098cb929d36f09b23",
            "subnet-063c1c46e0022789e",
            "subnet-03e66da10c9aa1db5",
            "subnet-055976e203588ff53",
            "subnet-0bf2cf472885db49b",
            "subnet-0a0503eebbd999db8",
            "subnet-07ab50af85218049f",
            "subnet-005d22e94c41c703c",
            "subnet-0a8924eed06d98aa2",
            "subnet-063384fce71257ee7",
            "subnet-0b8381697b1341238",
            "subnet-04ec85042e067facf",
            "subnet-01d7ecc3501508061",
            "subnet-072fe791bf38756b6",
            "subnet-0e9a04469d59f6b17",
            "subnet-0a3af4a496900fa01"
        }

        if 'Properties' in conf and 'Scheme' in conf['Properties']:
            scheme = str(conf['Properties']['Scheme']).lower()
            if 'internal' in scheme:
                return CheckResult.PASSED
            elif 'internet-facing' in scheme:
                if 'Subnets' in conf['Properties']:
                    if all(subnet in white_list for subnet in conf['Properties']['Subnets']):
                        return CheckResult.PASSED
                elif 'SubnetMappings' in conf['Properties']:
                    if all(subnet_mapping['SubnetId'] in white_list for subnet_mapping in conf['Properties']['SubnetMappings']):
                        return CheckResult.PASSED

        if 'Properties' in conf:
            if 'Subnets' in conf['Properties']:
                if all(subnet in white_list for subnet in conf['Properties']['Subnets']):
                    return CheckResult.PASSED
            elif 'SubnetMappings' in conf['Properties']:
                if all(subnet_mapping['SubnetId'] in white_list for subnet_mapping in conf['Properties']['SubnetMappings']):
                    return CheckResult.PASSED

        return CheckResult.FAILED
        


check = NLBInternetRestriction()
