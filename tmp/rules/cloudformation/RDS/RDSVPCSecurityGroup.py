from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSVPCSecurityGroup(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has not configurated DBSecurityGroups"
        id = "CKV_AWS_308"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'DBClusterIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'DBSecurityGroups' not in conf['Properties'].keys() and 'VPCSecurityGroups' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED

check = RDSVPCSecurityGroup()
