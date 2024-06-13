from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class SQSSecurityTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SQS has security tags"
        id = "CKV_AWS_337"
        supported_resources = ['AWS::SQS::Queue']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tagcc = False
        tagci = False
        tagcd = False
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if item['Key'] == "bancolombia:clasificacion-confidencialidad" and any(x for x in ["publica", "interna", "confidencial", "restringida"] if x in str(item['Value'])):
                                tagcc = True
                            elif item['Key'] == "bancolombia:clasificacion-integridad" and any(x for x in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico"] if x in str(item['Value'])):
                                tagci = True
                            elif item['Key'] == "bancolombia:clasificacion-disponibilidad" and any(x for x in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico"] if x in str(item['Value'])):
                                tagcd = True


        if tagcc and tagci and tagcd:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


check = SQSSecurityTags()
