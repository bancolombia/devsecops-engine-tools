from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from typing import List


def is_not_empty(a):
    return len(a) > 0


class EFSEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the EFS is securely encrypted"
        id = "CKV_AWS_318"
        supported_resources = ['AWS::EFS::FileSystem']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        properties = conf.get('Properties')
        if properties is not None:
            encrypted = properties.get('Encrypted')
            kmskeyid = properties.get('KmsKeyId')
            if encrypted and (kmskeyid is not None and is_not_empty(kmskeyid)):
                return CheckResult.PASSED
        return CheckResult.FAILED

    def get_evaluated_keys(self) -> List[str]:
        return ["Properties/Encrypted", "Properties/KmsKeyId"]


check = EFSEncryption()
