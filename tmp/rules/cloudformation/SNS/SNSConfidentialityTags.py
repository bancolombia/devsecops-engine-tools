from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class SNSConfidentiality(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SNS has confidentiality tags"
        id = "CKV_AWS_336"
        supported_resources = ['AWS::SNS::Topic']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            if  ":clasificacion-confidencialidad" in str(item['Key']) and item['Value'] in ["publica","interna","confidencial","restringida"]:
                                return CheckResult.PASSED

            return CheckResult.FAILED



check = SNSConfidentiality()
