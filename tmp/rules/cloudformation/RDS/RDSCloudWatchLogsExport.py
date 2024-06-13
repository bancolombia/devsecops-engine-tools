from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSCloudWatchLogsExport(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has CloudwatchLogsExports enabled"
        id = "CKV_AWS_309"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'DBClusterIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'EnableCloudwatchLogsExports' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED

check = RDSCloudWatchLogsExport()