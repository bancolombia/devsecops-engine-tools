from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

def is_not_empty(a):
    return len(a) > 0

class RDSEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the RDS is securely encrypted at rest"
        id = "CKV_AWS_256"
        supported_resources = ['AWS::RDS::DBInstance']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)
    
    def scan_resource_conf(self, conf):
        # If DB is Aurora then Encryption is set in other resource
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-storageencrypted
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
            if 'StorageEncrypted' in conf['Properties'].keys() and 'KmsKeyId' in conf['Properties'].keys():
                if conf['Properties']['StorageEncrypted'] in ["true",True] and is_not_empty(conf['Properties']['KmsKeyId']):
                    return CheckResult.PASSED
        return CheckResult.FAILED
  
check = RDSEncryption()
