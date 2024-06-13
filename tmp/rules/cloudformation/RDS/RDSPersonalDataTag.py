from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from Common import verified_tag, verified_listValues

class RDSPersonalDataTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS has personal data tag"
        id = "CKV_AWS_226"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.APPLICATION_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'Tags' in conf['Properties'].keys():
                if isinstance(conf['Properties']['Tags'], list):
                    for item in conf['Properties']['Tags']:
                        if 'Key' in item.keys() and 'Value' in item.keys():
                            ListValues= ["clientes", "proveedores", "empleados", "accionistas", "no"]
                            if item['Key'] in verified_tag("datos-personales") and verified_listValues(ListValues, item['Value'].split("-")):
                                return CheckResult.PASSED                                                                                                                                                                                                                                       
        return CheckResult.FAILED

check = RDSPersonalDataTag()