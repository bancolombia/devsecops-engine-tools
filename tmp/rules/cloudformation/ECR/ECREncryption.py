from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from typing import List




class ECREncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the ECR is securely encrypted"
        id = "CKV_AWS_392"
        supported_resources = ['AWS::ECR::Repository']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        properties = conf.get('Properties')
        if properties is not None:
            encrypted = properties.get('EncryptionConfiguration')
            if encrypted is not None:
                configurationType = encrypted.get('EncryptionType')
                kms = encrypted.get('KmsKey')
                if (configurationType == "KMS" and kms is not None):
                    return CheckResult.PASSED
        return CheckResult.FAILED



check = ECREncryption()
