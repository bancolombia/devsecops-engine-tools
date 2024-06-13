from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class LambdaTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Lambda has configured data clasification tags"
        id = "CKV_AWS_316"
        supported_resources = ['AWS::Lambda::Function']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tagCC = False
        tagCI = False
        tagCD = False
        if 'Properties' in conf.keys():
            if 'Code' in conf['Properties'].keys():
                if 'ZipFile' in conf['Properties']['Code']:
                    if 'headers' in str(conf['Properties']['Code']['ZipFile']):
                        return CheckResult.UNKNOWN
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] == "bancolombia:clasificacion-confidencialidad" and item['Value'] in ["publica", "interna", "confidencial", "restringida", "na"]:
                                tagCC = True
                            if item['Key'] == "bancolombia:clasificacion-integridad" and item['Value'] in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico", "na"]:
                                tagCI = True
                            if item['Key'] == "bancolombia:clasificacion-disponibilidad" and item['Value'] in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico", "na"]:
                                tagCD = True
        if tagCC and tagCI and tagCD:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


check = LambdaTags()
