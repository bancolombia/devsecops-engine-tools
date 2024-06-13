from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck


class KMSRotation(BaseResourceCheck):
    def __init__(self):
        name = "Ensure rotation for customer created CMKs is enabled"
        id = "CKV_AWS_329"
        supported_resources = ['AWS::KMS::Key']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'KeySpec' in conf['Properties'].keys():
                if "AES-256-GCM" not in conf['Properties']['KeySpec']:
                    return CheckResult.UNKNOWN
            if 'EnableKeyRotation' in conf['Properties'].keys():
                if "true" in str(conf['Properties']['EnableKeyRotation']).lower():
                    return CheckResult.PASSED
        return CheckResult.FAILED

check = KMSRotation()
