from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class NeptuneDR(BaseResourceCheck):

    def __init__(self):
        name = "Ensure Neptune has enable DR"
        id = "CKV_AWS_380"
        supported_resources = ['AWS::Neptune::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'AvailabilityZones' in conf['Properties'].keys():
                return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = NeptuneDR()
