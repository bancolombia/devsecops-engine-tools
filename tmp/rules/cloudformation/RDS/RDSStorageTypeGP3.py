from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
import re

class RDSStorageTypeGP3(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has not gp2 storage type "
        id = "CKV_AWS_400"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            try:
                if (conf['Properties']['Engine'] not in ['aurora-mysql', 'aurora-postgresql']) and(not re.search(r'.*Fn::FindInMap.*',str(conf['Properties']['Engine']))):
                    if 'StorageType' in conf['Properties'].keys():
                        if 'gp2' in str(conf['Properties']['StorageType']).lower():
                            return CheckResult.FAILED
                        else:
                            return CheckResult.PASSED
                else:
                    return CheckResult.PASSED
            except Exception:
                return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSStorageTypeGP3()