from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSAutomaticBackupPdn(BaseResourceCheck):

    def __init__(self):
        name = "Ensure that RDS instances has Automatic Backup configured"
        id = "CKV_AWS_297"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        try:
            if 'Properties' in conf.keys():
                if 'DBClusterIdentifier' in conf['Properties'].keys() or 'SourceDBInstanceIdentifier' in conf['Properties'].keys():
                    return CheckResult.UNKNOWN
                elif 'BackupRetentionPeriod' in conf['Properties'].keys():
                    valueBackupRetentionPeriod=conf['Properties']['BackupRetentionPeriod']
                    if isinstance(valueBackupRetentionPeriod, str) or isinstance(valueBackupRetentionPeriod, int):
                        if isinstance(valueBackupRetentionPeriod, str):
                            valueBackupRetentionPeriod = int(valueBackupRetentionPeriod)
                        if valueBackupRetentionPeriod >= 1 and valueBackupRetentionPeriod <= 35:
                            return CheckResult.PASSED
        except Exception as e:
            return CheckResult.FAILED
        return CheckResult.FAILED


check = RDSAutomaticBackupPdn()