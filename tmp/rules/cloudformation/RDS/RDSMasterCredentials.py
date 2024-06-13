from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class RDSMasterCredentials(BaseResourceCheck):
    def __init__(self):
        name = "Ensure master credentials RDS must be in Secret Manager"
        id = "CKV_AWS_303"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if 'DBSnapshotIdentifier' in conf['Properties'].keys():
                if 'Fn::If' in conf['Properties']['DBSnapshotIdentifier']:
                    blockFnIf = conf['Properties']['DBSnapshotIdentifier']['Fn::If']
                    position = 1
                    if 'empty' in blockFnIf[0]:
                        position = 2
                    if 'arn:aws:rds' in blockFnIf[position]:
                        return CheckResult.UNKNOWN
                else:
                    return CheckResult.UNKNOWN
            if 'DBClusterIdentifier' in conf['Properties'].keys() or 'SourceDBInstanceIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            if 'MasterUsername' in conf['Properties'].keys() and 'MasterUserPassword' in conf['Properties'].keys():
                if "secretsmanager" in str(conf['Properties']['MasterUsername']) and "secretsmanager" in str(conf['Properties']['MasterUserPassword']):
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSMasterCredentials()
