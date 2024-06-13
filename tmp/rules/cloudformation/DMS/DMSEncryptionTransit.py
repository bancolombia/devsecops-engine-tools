from typing import List
from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class DMSEncryptionTransit(BaseResourceCheck):

    def __init__(self):
        name = "Ensure DMS has enable data transit encryption"
        id = "CKV_AWS_347"
        supported_resources = ['AWS::DMS::Certificate']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'CertificateIdentifier' in conf['Properties'].keys() or 'CertificatePem' in conf['Properties'].keys() or 'CertificateWallet' in conf['Properties'].keys():
                return CheckResult.PASSED
            else: 
                return CheckResult.FAILED
        return CheckResult.FAILED


check = DMSEncryptionTransit()
