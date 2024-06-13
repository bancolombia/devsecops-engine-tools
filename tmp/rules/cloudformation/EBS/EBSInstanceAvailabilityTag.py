from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import verified_tag

class EBSInstanceAvailabilityTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EBS Instance has availability tag"
        id = "CKV_AWS_239"
        supported_resources = ['AWS::EC2::Instance']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        flag = False
        if 'Properties' in conf.keys():
            if 'BlockDeviceMappings' in conf['Properties'].keys(): 
                if isinstance(conf['Properties']['BlockDeviceMappings'], list):
                    for item in conf['Properties']['BlockDeviceMappings']:
                        if 'Ebs' in item.keys():
                            flag = True
                if 'Tags' in conf['Properties'].keys() and flag:
                    if isinstance(conf['Properties']['Tags'], list):
                        for item in conf['Properties']['Tags']:
                            if 'Key' in item.keys() and 'Value' in item.keys():
                                if item['Key'] in verified_tag("clasificacion-disponibilidad") and str(item['Value']) in ["sin-impacto","impacto-tolerable","impacto-moderado","impacto-critico","sin impacto","impacto tolerable","impacto moderado","impacto critico"]:
                                    return CheckResult.PASSED
        if not flag:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED

check = EBSInstanceAvailabilityTag()