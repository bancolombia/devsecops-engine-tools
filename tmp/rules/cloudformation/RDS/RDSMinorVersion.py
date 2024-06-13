from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSMinorVersion(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Minor version for AWS RDS"
        id = "CKV_AWS_343"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'AutoMinorVersionUpgrade' in conf['Properties'].keys():
                return CheckResult.PASSED
            return CheckResult.PASSED


check = RDSMinorVersion()
