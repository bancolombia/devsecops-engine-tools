
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class AuroraCloudwatchLogsExports(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Aurora has CloudwatchLogsExports enabled"
        id = "CKV_AWS_307"
        supported_resources = ['AWS::RDS::DBCluster']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'EngineMode' in conf['Properties'].keys() and 'serverless' in str(conf['Properties']['EngineMode']).lower():
                return CheckResult.UNKNOWN
            elif 'EnableCloudwatchLogsExports' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED


check = AuroraCloudwatchLogsExports()
