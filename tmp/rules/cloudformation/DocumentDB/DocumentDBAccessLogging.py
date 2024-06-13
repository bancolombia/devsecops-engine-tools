from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class DocumentDBAccessLogging(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DocumentDB access logging is enabled"
        id = "CKV_AWS_352"
        supported_resources = ['AWS::DocDB::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'Properties' in conf.keys():
            if 'EnableCloudwatchLogsExports' in conf['Properties'].keys():
                return CheckResult.PASSED
        return CheckResult.FAILED
    
check = DocumentDBAccessLogging()


