from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import verified_tag

class RDSIntegrityTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS has integrity tag"
        id = "CKV_AWS_222"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] in verified_tag("clasificacion-integridad") and item['Value'] in ["sin-impacto","impacto-tolerable","impacto-moderado","impacto-critico","sin impacto","impacto tolerable","impacto moderado","impacto critico"]:
                                return CheckResult.PASSED
        return CheckResult.FAILED

check = RDSIntegrityTag()