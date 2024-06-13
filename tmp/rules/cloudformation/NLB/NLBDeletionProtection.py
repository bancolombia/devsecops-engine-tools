from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class NLBDeletedProtection(BaseResourceCheck):
    def __init__(self):
        name = "Ensure NLB has deletion protection"
        id = "CKV_AWS_371"
        supported_resources = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "Properties" in conf.keys():
            if "Type" in conf["Properties"].keys():
                if "network" in str(conf["Properties"]["Type"]).lower():
                    if "LoadBalancerAttributes" in conf["Properties"].keys():
                        if isinstance(conf["Properties"]["LoadBalancerAttributes"], list):
                            for item in conf["Properties"]["LoadBalancerAttributes"]:
                                if "Key" in item.keys() and "Value" in item.keys():
                                    if item["Key"] == "deletion_protection.enabled" and str(item["Value"]).lower() == "true":
                                        return CheckResult.PASSED
                            return CheckResult.FAILED
                    else:
                        return CheckResult.FAILED


check = NLBDeletedProtection()
