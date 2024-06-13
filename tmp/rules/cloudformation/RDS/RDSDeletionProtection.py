from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSDeletionProtection(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has Deletion Protection"
        id = "CKV_AWS_275"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Condition' in conf['Properties'] and 'datical' in str(conf['Properties']['Condition']).lower():
                return CheckResult.UNKNOWN
            elif 'DBClusterIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'DeletionProtection' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['DeletionProtection']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSDeletionProtection()