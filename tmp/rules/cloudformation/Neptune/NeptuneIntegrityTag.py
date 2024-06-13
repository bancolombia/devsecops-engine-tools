from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class NeptuneIntegrityTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Neptune has integrity tag"
        id = "CKV_AWS_382"
        supported_resources = ['AWS::Neptune::DBInstance']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if  ":clasificacion-integridad" in str(item['Key']) and item['Value'] in ["sin impacto","impacto tolerable","impacto moderado","impacto critico"]:
                                return CheckResult.PASSED
        return CheckResult.FAILED

check = NeptuneIntegrityTag()