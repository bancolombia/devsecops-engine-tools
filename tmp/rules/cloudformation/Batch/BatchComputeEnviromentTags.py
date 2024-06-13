from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class BatchComputeEnviromentTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Batch Compute Enviroment has security tags"
        id = "CKV_AWS_365"
        supported_resources = ['AWS::Batch::ComputeEnvironment']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tagcc = False
        tagci = False
        tagcd = False
        
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                items = conf['Properties']['Tags']
                if 'bancolombia:clasificacion-confidencialidad' in items:
                    if any(x for x in ["publica", "interna", "confidencial", "restringida"] if items['bancolombia:clasificacion-confidencialidad'] in x):
                        tagcc = True
                if 'bancolombia:clasificacion-integridad' in items:
                    if any(x for x in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico"] if items['bancolombia:clasificacion-integridad'] in x):
                        tagci = True
                if 'bancolombia:clasificacion-disponibilidad' in items:
                    if any(x for x in ["sin impacto", "impacto tolerable", "impacto moderado", "impacto critico"] if items['bancolombia:clasificacion-disponibilidad'] in x):
                        tagcd = True


        if tagcc and tagci and tagcd:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


check = BatchComputeEnviromentTags()
