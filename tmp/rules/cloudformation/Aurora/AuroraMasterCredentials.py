from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class AuroraMasterCredentials(BaseResourceCheck):
    def __init__(self):
        name = "Ensure master credentials Aurora must be in Secret Manager"
        id = "CKV_AWS_289"
        supported_resources = ['AWS::RDS::DBCluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        if 'Properties' in conf.keys():
            if any(x for x in ['SourceDBClusterIdentifier','SnapshotIdentifier', 'GlobalClusterIdentifier'] if x in conf['Properties'].keys()):
                return CheckResult.UNKNOWN
            elif 'MasterUsername' in conf['Properties'].keys() and 'MasterUserPassword' in conf['Properties'].keys():
                if "secretsmanager" in str(conf['Properties']['MasterUsername']) and "secretsmanager" in str(conf['Properties']['MasterUserPassword']):
                    return CheckResult.PASSED
        return CheckResult.FAILED


check = AuroraMasterCredentials()
