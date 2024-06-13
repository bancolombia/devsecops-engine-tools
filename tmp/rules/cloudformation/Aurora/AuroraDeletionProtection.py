from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class AuroraDeletionProtection(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that Aurora has Deletion Protection"
        id = "CKV_AWS_288"
        supported_resources = ['AWS::RDS::DBCluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Condition' in conf['Properties'] and 'datical' in str(conf['Properties']['Condition']).lower():
                return CheckResult.UNKNOWN
            elif 'DeletionProtection' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['DeletionProtection']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = AuroraDeletionProtection()