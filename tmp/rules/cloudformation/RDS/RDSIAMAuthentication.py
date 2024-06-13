from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSIAMAuthentication(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has not IAM Authentication enabled"
        id = "CKV_AWS_340"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'EnableIAMDatabaseAuthentication' in conf['Properties'].keys():
                if 'true' in str(conf['Properties']['EnableIAMDatabaseAuthentication']).lower():
                    return CheckResult.FAILED
        return CheckResult.PASSED


check = RDSIAMAuthentication()
