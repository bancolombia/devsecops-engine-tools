from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class DocumentDBSecureProtocol(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DocumentDB has secure protocol enabled"
        id = "CKV_AWS_353"
        supported_resources = ['AWS::DocDB::DBClusterParameterGroup']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Parameters' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Parameters'], dict):
                    if 'tls' in conf['Properties']['Parameters']:
                        if conf['Properties']['Parameters']['tls'] == "enabled":
                            return CheckResult.PASSED

        return CheckResult.FAILED
    
check = DocumentDBSecureProtocol()