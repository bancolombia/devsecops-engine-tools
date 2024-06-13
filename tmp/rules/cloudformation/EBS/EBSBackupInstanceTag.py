from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class EBSBackupInstanceTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EBS has tag backup instance"
        id = "CKV_AWS_326"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] == "bancolombia:bkmensual":
                                if item['Value'] in ["ebs","no"]:
                                    return CheckResult.PASSED
        return CheckResult.FAILED

check = EBSBackupInstanceTag()