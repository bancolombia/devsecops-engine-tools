from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSMajorVersion(BaseResourceCheck):
    def __init__(self):
        name = "Ensure major version for AWS RDS"
        id = "CKV_AWS_344"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'AllowMajorVersionUpgrade' in conf['Properties'].keys():
                if 'false' in str(conf['Properties']['AllowMajorVersionUpgrade']).lower():
                    return CheckResult.FAILED
                return CheckResult.PASSED
            return CheckResult.FAILED


check = RDSMajorVersion()
