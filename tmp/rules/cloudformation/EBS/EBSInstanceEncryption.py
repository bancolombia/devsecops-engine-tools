from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


def is_not_empty(a):
    return len(a) > 0

class EBSInstanceEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the EBS Instance is securely encrypted"
        id = "CKV_AWS_271"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        contebs=0
        contebsok=0
        if 'Properties' in conf.keys():
            if 'BlockDeviceMappings' in conf['Properties'].keys(): 
                if isinstance(conf['Properties']['BlockDeviceMappings'], list):
                    for item in conf['Properties']['BlockDeviceMappings']:
                        if 'Ebs' in item.keys():
                            contebs = contebs + 1
                            if 'Encrypted' in item['Ebs'] and 'KmsKeyId' in item['Ebs']:
                                if item['Ebs']['Encrypted'] in ["true",True] and is_not_empty(item['Ebs']['KmsKeyId']):
                                    contebsok = contebsok + 1
                if contebs == contebsok:
                    return CheckResult.PASSED
                else:
                    return CheckResult.FAILED        
            else:
                return CheckResult.PASSED
        return CheckResult.FAILED

check = EBSInstanceEncryption()