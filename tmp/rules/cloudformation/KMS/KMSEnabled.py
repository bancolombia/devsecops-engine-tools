from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class KMSEnabled(BaseResourceCheck):
    def __init__(self):
        name = "Ensure KMS is enabled"
        id = "CKV_AWS_294"
        supported_resources = ['AWS::KMS::Key']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Enabled' not in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            else:
                if "true" in str(conf['Properties']['Enabled']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = KMSEnabled()
