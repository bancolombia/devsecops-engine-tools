from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class KDFEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure KDF has encryption"
        id = "CKV_AWS_398"
        supported_resources = ['AWS::KinesisFirehose::DeliveryStream']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'DeliveryStreamEncryptionConfigurationInput' in conf['Properties'].keys():
                if 'KeyType' in conf['Properties']['DeliveryStreamEncryptionConfigurationInput'].keys():
                    if conf['Properties']['DeliveryStreamEncryptionConfigurationInput']['KeyType'] == 'AWS_OWNED_CMK':
                        return CheckResult.PASSED            
        return CheckResult.FAILED
    
check = KDFEncryption()