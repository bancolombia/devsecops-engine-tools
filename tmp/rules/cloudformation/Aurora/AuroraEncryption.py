from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

def is_not_empty(a):
    return len(a) > 0

class AuroraEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in Aurora is securely encrypted at rest"
        id = "CKV_AWS_259"
        supported_resources = ['AWS::RDS::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # If you specify the SnapshotIdentifier or SourceDBInstanceIdentifier property, don't specify this property. 
        # The value is inherited from the snapshot or source DB instance.
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#cfn-rds-dbcluster-storageencrypted
        # Doc refers to 'SourceDBInstanceIdentifier' but that is not an available field. This is a doc error. 'SourceDBClusterIdentifier' is correct.
        if 'Properties' in conf.keys():
            if 'SnapshotIdentifier' in conf['Properties'].keys() or 'SourceDBClusterIdentifier' in conf['Properties'].keys():
                return CheckResult.UNKNOWN
            elif 'StorageEncrypted' in conf['Properties'].keys() and 'KmsKeyId' in conf['Properties'].keys():
                if conf['Properties']['StorageEncrypted'] in ["true",True] and is_not_empty(conf['Properties']['KmsKeyId']):
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = AuroraEncryption()