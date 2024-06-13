from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSSupportDatabase(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances use supported database engine versions"
        id = "CKV_AWS_341"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'Engine' in conf['Properties'].keys() and 'EngineVersion' in conf['Properties'].keys():
                if 'sqlserver' in conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '15.00.4073.23':
                        return CheckResult.FAILED
                if 'mysql' == conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '8.0.28':
                        return CheckResult.FAILED
                if 'oracle' in conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '19':
                        return CheckResult.FAILED
                if 'postgres' in conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '14.2':
                        return CheckResult.FAILED
                if 'aurora-mysql' in conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '3.01.0':
                        return CheckResult.FAILED
                if 'aurora-postgresql' in conf['Properties']['Engine']:
                    if str(conf['Properties']['EngineVersion']).lower() < '14.2':
                        return CheckResult.FAILED
            return CheckResult.PASSED
        return CheckResult.PASSED

check = RDSSupportDatabase()
