from checkov.cloudformation.checks.resource.base_resource_value_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class APIGatewayRestApiXRay(BaseResourceCheck):

    def __init__(self):
        name = "AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages."
        id = "CKV_AWS_420"
        supported_resources = ['AWS::ApiGateway::Stage']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if conf['Type'] == 'AWS::ApiGateway::Stage':
            if 'Properties' in conf.keys():
                if 'RestApiId' not in conf['Properties'].keys():
                    return CheckResult.FAILED
                if 'TracingEnabled' in conf['Properties'].keys():
                    if conf['Properties']['TracingEnabled']: 
                        return CheckResult.PASSED
                    else:
                        return CheckResult.FAILED
                else:
                    return CheckResult.FAILED
            else:
                return CheckResult.FAILED

check = APIGatewayRestApiXRay()